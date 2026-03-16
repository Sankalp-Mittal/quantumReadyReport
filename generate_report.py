#!/usr/bin/env python3
"""
PQC CBOM Report Generator
Reads a CBOM JSON file and produces a self-contained HTML dashboard.
Usage: python3 generate_report.py cbom_20260316_120000.json
"""

import json
import sys
import os
from datetime import datetime, timezone

# ── Load CBOM ─────────────────────────────────────────────────────
def load_cbom(path):
    with open(path) as f:
        return json.load(f)

# ── Label helpers ──────────────────────────────────────────────────
LABEL_META = {
    "FULLY_QUANTUM_SAFE": {
        "badge": "✦ Fully Quantum Safe",
        "css": "label-fqs",
        "short": "FQS",
        "desc": "Implements NIST-standardised PQC for key exchange, authentication and symmetric encryption."
    },
    "PQC_READY": {
        "badge": "◈ PQC Ready",
        "css": "label-pqc",
        "short": "PQC",
        "desc": "PQC key exchange in use. Certificate migration to ML-DSA pending."
    },
    "NOT_PQC_READY": {
        "badge": "◇ Not PQC Ready",
        "css": "label-notpqc",
        "short": "NOT PQC",
        "desc": "Classical cryptography only. Vulnerable to Shor's algorithm on CRQCs."
    },
    "CRITICAL": {
        "badge": "✖ Critical",
        "css": "label-critical",
        "short": "CRIT",
        "desc": "Broken or severely weakened cipher suite detected. Immediate action required."
    },
    "ERROR": {
        "badge": "— Error",
        "css": "label-error",
        "short": "ERR",
        "desc": "Could not connect to host."
    }
}

def get_label(asset):
    if "error" in asset:
        return "ERROR"
    return asset.get("quantum_assessment", {}).get("label", "NOT_PQC_READY")

def safe(asset, *keys, default="—"):
    try:
        v = asset
        for k in keys:
            v = v[k]
        return v if v not in (None, "", "unknown") else default
    except (KeyError, TypeError):
        return default

# ── Build summary stats ────────────────────────────────────────────
def compute_stats(assets):
    counts = {"FULLY_QUANTUM_SAFE": 0, "PQC_READY": 0, "NOT_PQC_READY": 0, "CRITICAL": 0, "ERROR": 0}
    for a in assets:
        counts[get_label(a)] = counts.get(get_label(a), 0) + 1
    return counts

# ── Render a single asset card ─────────────────────────────────────
def render_asset_card(asset):
    label = get_label(asset)
    meta = LABEL_META.get(label, LABEL_META["ERROR"])

    if label == "ERROR":
        return f"""
        <div class="asset-card error-card">
          <div class="card-header">
            <span class="host-name">{asset.get('host','?')}:{asset.get('port',443)}</span>
            <span class="label-badge {meta['css']}">{meta['badge']}</span>
          </div>
          <p class="error-msg">Connection failed — host unreachable or port closed.</p>
        </div>"""

    conn = asset.get("connection", {})
    kex  = asset.get("key_exchange", {})
    cert = asset.get("certificate", {})
    qa   = asset.get("quantum_assessment", {})
    recs = asset.get("recommendations", [])

    kex_class  = kex.get("classification","unknown")
    cert_class = cert.get("classification","unknown")
    sym_class  = asset.get("symmetric",{}).get("classification","unknown")

    def dot(ok):
        if ok == "safe" or ok is True or ok in ("pqc","pqc_hybrid","pqc_pure"):
            return '<span class="dot dot-safe"></span>'
        elif ok in ("marginal",):
            return '<span class="dot dot-warn"></span>'
        else:
            return '<span class="dot dot-vuln"></span>'

    kex_dot  = dot(kex_class)
    cert_dot = dot(cert_class)
    sym_dot  = dot(sym_class)

    days = cert.get("days_until_expiry", 9999)
    expiry_class = ""
    if isinstance(days, int):
        if days < 0:    expiry_class = "expiry-expired"
        elif days < 30: expiry_class = "expiry-soon"

    recs_html = "".join(f'<li>{r}</li>' for r in recs)
    vulns = qa.get("vulnerabilities", [])
    vulns_html = "".join(f'<li>{v}</li>' for v in vulns)

    scan_time = asset.get("scan_time","")[:19].replace("T"," ") + " UTC"

    return f"""
    <div class="asset-card" data-label="{label}">
      <div class="card-header">
        <div class="host-info">
          <span class="host-name">{asset['host']}</span>
          <span class="host-port">:{asset['port']}</span>
        </div>
        <span class="label-badge {meta['css']}">{meta['badge']}</span>
      </div>

      <div class="card-grid">
        <div class="card-section">
          <div class="section-title">TLS</div>
          <div class="kv"><span class="k">Version</span><span class="v">{safe(conn,'tls_version')}</span></div>
          <div class="kv"><span class="k">Cipher</span><span class="v cipher-text">{safe(conn,'cipher_suite')}</span></div>
          <div class="kv"><span class="k">Verified</span><span class="v">{safe(conn,'verify')}</span></div>
        </div>

        <div class="card-section">
          <div class="section-title">Quantum Analysis</div>
          <div class="kv">{kex_dot}<span class="k">Key exchange</span><span class="v">{safe(kex,'algorithm')}</span></div>
          <div class="kv">{cert_dot}<span class="k">Certificate</span><span class="v">{safe(cert,'key_type')} ({safe(cert,'key_bits')}-bit)</span></div>
          <div class="kv">{sym_dot}<span class="k">Symmetric</span><span class="v">{safe(conn,'enc_algorithm')}</span></div>
        </div>

        <div class="card-section">
          <div class="section-title">Certificate</div>
          <div class="kv"><span class="k">Subject</span><span class="v small-text">{safe(cert,'subject')}</span></div>
          <div class="kv"><span class="k">Issuer</span><span class="v small-text">{safe(cert,'issuer')}</span></div>
          <div class="kv"><span class="k">Expires</span><span class="v {expiry_class}">{safe(cert,'not_after')} ({days} days)</span></div>
          <div class="kv"><span class="k">Chain</span><span class="v">{safe(cert,'chain_depth')} cert(s)</span></div>
        </div>
      </div>

      {"<div class='vuln-block'><div class='section-title'>Vulnerabilities</div><ul>" + vulns_html + "</ul></div>" if vulns else ""}
      {"<div class='rec-block'><div class='section-title'>Recommendations</div><ul>" + recs_html + "</ul></div>" if recs else ""}

      <div class="card-footer">Scanned {scan_time}</div>
    </div>"""

# ── Main render ────────────────────────────────────────────────────
def render_html(cbom):
    assets = cbom.get("assets", [])
    stats  = compute_stats(assets)
    total  = len(assets)
    scan_start = cbom.get("scan_start","")[:19].replace("T"," ")

    cards_html = "\n".join(render_asset_card(a) for a in assets)

    fqs_pct  = round(stats["FULLY_QUANTUM_SAFE"] / total * 100) if total else 0
    pqc_pct  = round(stats["PQC_READY"] / total * 100) if total else 0
    npqc_pct = round(stats["NOT_PQC_READY"] / total * 100) if total else 0
    crit_pct = round(stats["CRITICAL"] / total * 100) if total else 0

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PQC CBOM Report — {scan_start}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=Syne:wght@400;600;800&display=swap" rel="stylesheet">
<style>
  :root {{
    --bg:       #0a0c10;
    --bg2:      #111419;
    --bg3:      #181c22;
    --border:   #1e2430;
    --border2:  #2a3040;
    --text:     #c8d0e0;
    --text2:    #7a8499;
    --text3:    #4a5266;
    --accent:   #00e5ff;
    --fqs:      #00ff94;
    --pqc:      #00cfff;
    --notpqc:   #f5a623;
    --critical: #ff4d4d;
    --error:    #666;
    --font-head: 'Syne', sans-serif;
    --font-mono: 'IBM Plex Mono', monospace;
  }}
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  html {{ font-size: 14px; }}
  body {{
    background: var(--bg);
    color: var(--text);
    font-family: var(--font-mono);
    line-height: 1.6;
    min-height: 100vh;
  }}

  /* ── Header ── */
  .site-header {{
    border-bottom: 1px solid var(--border);
    padding: 2rem 2.5rem 1.5rem;
    display: flex;
    align-items: flex-end;
    justify-content: space-between;
    gap: 1rem;
    flex-wrap: wrap;
  }}
  .site-header h1 {{
    font-family: var(--font-head);
    font-size: 1.9rem;
    font-weight: 800;
    letter-spacing: -0.03em;
    color: #fff;
  }}
  .site-header h1 span {{ color: var(--accent); }}
  .header-meta {{
    font-size: 0.78rem;
    color: var(--text3);
    text-align: right;
    line-height: 1.8;
  }}

  /* ── Filter bar ── */
  .filter-bar {{
    padding: 1rem 2.5rem;
    border-bottom: 1px solid var(--border);
    display: flex;
    gap: 0.5rem;
    flex-wrap: wrap;
    align-items: center;
  }}
  .filter-label {{ color: var(--text3); font-size: 0.75rem; margin-right: 0.5rem; }}
  .filter-btn {{
    padding: 0.3rem 0.9rem;
    border-radius: 2px;
    border: 1px solid var(--border2);
    background: var(--bg2);
    color: var(--text2);
    font-family: var(--font-mono);
    font-size: 0.75rem;
    cursor: pointer;
    transition: all 0.15s;
    letter-spacing: 0.03em;
  }}
  .filter-btn:hover {{ border-color: var(--accent); color: var(--accent); }}
  .filter-btn.active {{ background: var(--accent); color: #000; border-color: var(--accent); font-weight: 600; }}

  /* ── Stats bar ── */
  .stats-bar {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 1px;
    background: var(--border);
    border-bottom: 1px solid var(--border);
  }}
  .stat-cell {{
    background: var(--bg2);
    padding: 1.2rem 1.5rem;
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
  }}
  .stat-num {{
    font-family: var(--font-head);
    font-size: 2.2rem;
    font-weight: 800;
    line-height: 1;
  }}
  .stat-label {{ font-size: 0.72rem; color: var(--text3); letter-spacing: 0.08em; text-transform: uppercase; }}
  .stat-pct {{ font-size: 0.72rem; color: var(--text3); }}
  .stat-fqs   .stat-num {{ color: var(--fqs); }}
  .stat-pqc   .stat-num {{ color: var(--pqc); }}
  .stat-notpqc .stat-num {{ color: var(--notpqc); }}
  .stat-crit  .stat-num {{ color: var(--critical); }}
  .stat-total .stat-num {{ color: #fff; }}

  /* ── Progress bar ── */
  .progress-bar {{
    height: 3px;
    display: flex;
    background: var(--bg);
  }}
  .pb-fqs   {{ background: var(--fqs);      width: {fqs_pct}%; }}
  .pb-pqc   {{ background: var(--pqc);      width: {pqc_pct}%; }}
  .pb-notpqc{{ background: var(--notpqc);   width: {npqc_pct}%; }}
  .pb-crit  {{ background: var(--critical); width: {crit_pct}%; }}

  /* ── Main content ── */
  .main {{ padding: 2rem 2.5rem; }}
  .assets-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(560px, 1fr));
    gap: 1px;
    background: var(--border);
    border: 1px solid var(--border);
  }}

  /* ── Asset card ── */
  .asset-card {{
    background: var(--bg2);
    padding: 1.4rem 1.6rem;
    transition: background 0.15s;
  }}
  .asset-card:hover {{ background: var(--bg3); }}
  .error-card {{ opacity: 0.5; }}
  .card-header {{
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 1rem;
    margin-bottom: 1rem;
    flex-wrap: wrap;
  }}
  .host-name {{ font-family: var(--font-head); font-size: 1.05rem; font-weight: 700; color: #fff; }}
  .host-port {{ color: var(--text3); font-size: 0.9rem; }}

  /* ── Labels ── */
  .label-badge {{
    font-size: 0.68rem;
    font-weight: 600;
    padding: 0.22rem 0.65rem;
    border-radius: 2px;
    letter-spacing: 0.06em;
    white-space: nowrap;
    text-transform: uppercase;
  }}
  .label-fqs    {{ background: rgba(0,255,148,0.12); color: var(--fqs);      border: 1px solid rgba(0,255,148,0.3); }}
  .label-pqc    {{ background: rgba(0,207,255,0.12); color: var(--pqc);      border: 1px solid rgba(0,207,255,0.3); }}
  .label-notpqc {{ background: rgba(245,166,35,0.12); color: var(--notpqc); border: 1px solid rgba(245,166,35,0.3); }}
  .label-critical{{ background: rgba(255,77,77,0.12); color: var(--critical);border: 1px solid rgba(255,77,77,0.3); }}
  .label-error  {{ background: rgba(100,100,100,0.1); color: var(--text3);   border: 1px solid var(--border2); }}

  /* ── Card grid ── */
  .card-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
    gap: 1rem 1.5rem;
    margin-bottom: 1rem;
  }}
  .section-title {{
    font-size: 0.65rem;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--text3);
    margin-bottom: 0.5rem;
    padding-bottom: 0.3rem;
    border-bottom: 1px solid var(--border);
  }}
  .kv {{ display: flex; align-items: baseline; gap: 0.4rem; margin-bottom: 0.3rem; flex-wrap: wrap; }}
  .k {{ font-size: 0.72rem; color: var(--text3); white-space: nowrap; }}
  .v {{ font-size: 0.75rem; color: var(--text); word-break: break-all; }}
  .cipher-text {{ font-size: 0.68rem; color: var(--accent); }}
  .small-text {{ font-size: 0.65rem; }}

  /* ── Status dots ── */
  .dot {{ display: inline-block; width: 7px; height: 7px; border-radius: 50%; margin-right: 0.3rem; flex-shrink: 0; }}
  .dot-safe {{ background: var(--fqs); }}
  .dot-warn {{ background: var(--notpqc); }}
  .dot-vuln {{ background: var(--critical); }}

  /* ── Expiry ── */
  .expiry-expired {{ color: var(--critical); font-weight: 600; }}
  .expiry-soon    {{ color: var(--notpqc); }}

  /* ── Vuln/rec blocks ── */
  .vuln-block, .rec-block {{
    margin-top: 0.8rem;
    padding: 0.8rem 1rem;
    border-radius: 2px;
    font-size: 0.75rem;
  }}
  .vuln-block {{
    background: rgba(255,77,77,0.06);
    border-left: 2px solid var(--critical);
  }}
  .rec-block {{
    background: rgba(0,229,255,0.04);
    border-left: 2px solid var(--accent);
  }}
  .vuln-block ul, .rec-block ul {{ padding-left: 1.2rem; }}
  .vuln-block li, .rec-block li {{ margin-bottom: 0.3rem; color: var(--text2); }}
  .vuln-block .section-title {{ color: var(--critical); border-color: rgba(255,77,77,0.2); }}
  .rec-block .section-title  {{ color: var(--accent);   border-color: rgba(0,229,255,0.15); }}

  .card-footer {{
    margin-top: 1rem;
    font-size: 0.65rem;
    color: var(--text3);
    text-align: right;
  }}
  .error-msg {{ font-size: 0.78rem; color: var(--text3); padding: 0.5rem 0; }}

  /* ── Footer ── */
  .site-footer {{
    border-top: 1px solid var(--border);
    padding: 1.5rem 2.5rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 0.72rem;
    color: var(--text3);
    flex-wrap: wrap;
    gap: 0.5rem;
  }}
  .legend {{ display: flex; gap: 1.2rem; flex-wrap: wrap; }}
  .legend-item {{ display: flex; align-items: center; gap: 0.4rem; }}

  /* ── Hidden ── */
  .hidden {{ display: none !important; }}
</style>
</head>
<body>

<header class="site-header">
  <div>
    <h1>PQC <span>CBOM</span> Report</h1>
    <div style="font-size:0.75rem;color:var(--text3);margin-top:0.3rem;">
      Cryptographic Bill of Materials — Quantum Readiness Assessment
    </div>
  </div>
  <div class="header-meta">
    <div>Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</div>
    <div>Scan start: {scan_start} UTC</div>
    <div>Generator: {cbom.get('generator','PQC CBOM Scanner')}</div>
  </div>
</header>

<div class="progress-bar">
  <div class="pb-fqs"></div>
  <div class="pb-pqc"></div>
  <div class="pb-notpqc"></div>
  <div class="pb-crit"></div>
</div>

<div class="stats-bar">
  <div class="stat-cell stat-total">
    <div class="stat-num">{total}</div>
    <div class="stat-label">Total assets</div>
  </div>
  <div class="stat-cell stat-fqs">
    <div class="stat-num">{stats['FULLY_QUANTUM_SAFE']}</div>
    <div class="stat-label">Fully quantum safe</div>
    <div class="stat-pct">{fqs_pct}%</div>
  </div>
  <div class="stat-cell stat-pqc">
    <div class="stat-num">{stats['PQC_READY']}</div>
    <div class="stat-label">PQC ready</div>
    <div class="stat-pct">{pqc_pct}%</div>
  </div>
  <div class="stat-cell stat-notpqc">
    <div class="stat-num">{stats['NOT_PQC_READY']}</div>
    <div class="stat-label">Not PQC ready</div>
    <div class="stat-pct">{npqc_pct}%</div>
  </div>
  <div class="stat-cell stat-crit">
    <div class="stat-num">{stats['CRITICAL']}</div>
    <div class="stat-label">Critical</div>
    <div class="stat-pct">{crit_pct}%</div>
  </div>
</div>

<div class="filter-bar">
  <span class="filter-label">Filter:</span>
  <button class="filter-btn active" onclick="filter('ALL')">All ({total})</button>
  <button class="filter-btn" onclick="filter('FULLY_QUANTUM_SAFE')">✦ Quantum Safe ({stats['FULLY_QUANTUM_SAFE']})</button>
  <button class="filter-btn" onclick="filter('PQC_READY')">◈ PQC Ready ({stats['PQC_READY']})</button>
  <button class="filter-btn" onclick="filter('NOT_PQC_READY')">◇ Not PQC Ready ({stats['NOT_PQC_READY']})</button>
  <button class="filter-btn" onclick="filter('CRITICAL')">✖ Critical ({stats['CRITICAL']})</button>
</div>

<main class="main">
  <div class="assets-grid" id="assets-grid">
    {cards_html}
  </div>
</main>

<footer class="site-footer">
  <div>CBOM file: {os.path.basename(cbom.get('_source','cbom.json'))}</div>
  <div class="legend">
    <div class="legend-item"><span class="dot dot-safe"></span> PQC / Safe</div>
    <div class="legend-item"><span class="dot dot-warn"></span> Marginal</div>
    <div class="legend-item"><span class="dot dot-vuln"></span> Vulnerable</div>
  </div>
  <div>PNB Cybersecurity Hackathon 2025-26</div>
</footer>

<script>
function filter(label) {{
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('.asset-card').forEach(card => {{
    if (label === 'ALL' || card.dataset.label === label) {{
      card.classList.remove('hidden');
    }} else {{
      card.classList.add('hidden');
    }}
  }});
}}
</script>
</body>
</html>"""

# ── Entry point ────────────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 generate_report.py <cbom.json>")
        sys.exit(1)

    cbom_path = sys.argv[1]
    if not os.path.exists(cbom_path):
        print(f"Error: file not found: {cbom_path}")
        sys.exit(1)

    cbom = load_cbom(cbom_path)
    cbom["_source"] = cbom_path

    output_dir = os.path.dirname(cbom_path)
    timestamp  = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path   = os.path.join(output_dir, f"pqc_report_{timestamp}.html")

    html = render_html(cbom)
    with open(out_path, "w") as f:
        f.write(html)

    print(f"Report generated: {out_path}")
