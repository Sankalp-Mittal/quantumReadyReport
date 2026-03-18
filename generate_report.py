#!/usr/bin/env python3
"""
PQC CBOM Report Generator
Reads a CBOM JSON file and produces a self-contained HTML dashboard.
Usage: python3 generate_report.py cbom_20260316_120000.json
"""

import json
import sys
import os
from collections import OrderedDict
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

# Severity order for "worst label" calculation (higher = worse)
_SEVERITY = {"FULLY_QUANTUM_SAFE": 0, "PQC_READY": 1, "ERROR": 2,
             "NOT_PQC_READY": 3, "CRITICAL": 4}

def get_label(asset):
    if "error" in asset:
        return "ERROR"
    return asset.get("quantum_assessment", {}).get("label", "NOT_PQC_READY")

def worst_label(assets):
    return max((get_label(a) for a in assets), key=lambda l: _SEVERITY.get(l, 0))

def safe(asset, *keys, default="—"):
    try:
        v = asset
        for k in keys:
            v = v[k]
        return v if v not in (None, "", "unknown") else default
    except (KeyError, TypeError):
        return default

# ── Domain grouping ────────────────────────────────────────────────
def root_domain(hostname):
    """Return the eTLD+1 approximation (last two labels, strip port)."""
    hostname = hostname.split(":")[0]
    parts = hostname.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else hostname

def group_assets(assets):
    """
    Returns OrderedDict { root_domain: [asset, ...] }
    The root asset (if present) is always first in each list.
    """
    groups = OrderedDict()
    for a in assets:
        host = a.get("host", "")
        rd = root_domain(host)
        groups.setdefault(rd, []).append(a)

    # Within each group, sort so the exact root domain comes first
    for rd, members in groups.items():
        members.sort(key=lambda a: (0 if root_domain(a.get("host","")) == a.get("host","").split(":")[0] else 1,
                                    a.get("host", "")))
    return groups

# ── Build summary stats ────────────────────────────────────────────
def compute_stats(assets):
    counts = {"FULLY_QUANTUM_SAFE": 0, "PQC_READY": 0, "NOT_PQC_READY": 0, "CRITICAL": 0, "ERROR": 0}
    for a in assets:
        counts[get_label(a)] = counts.get(get_label(a), 0) + 1
    return counts

# ── Dot helper ────────────────────────────────────────────────────
def dot(ok):
    if ok in ("safe", True, "pqc", "pqc_hybrid", "pqc_pure"):
        return '<span class="dot dot-safe"></span>'
    elif ok == "marginal":
        return '<span class="dot dot-warn"></span>'
    else:
        return '<span class="dot dot-vuln"></span>'

# ── Full asset card (root domain / single host) ────────────────────
def render_asset_card(asset, subdomain_count=0, group_id=""):
    label = get_label(asset)
    meta  = LABEL_META.get(label, LABEL_META["ERROR"])

    if label == "ERROR":
        return f"""
        <div class="asset-card error-card" data-label="{label}">
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

    kex_class  = kex.get("classification", "unknown")
    cert_class = cert.get("classification", "unknown")
    sym_class  = asset.get("symmetric", {}).get("classification", "unknown")

    days = cert.get("days_until_expiry", 9999)
    expiry_class = ""
    if isinstance(days, int):
        if days < 0:    expiry_class = "expiry-expired"
        elif days < 30: expiry_class = "expiry-soon"

    recs_html  = "".join(f'<li>{r}</li>' for r in recs)
    vulns      = qa.get("vulnerabilities", [])
    vulns_html = "".join(f'<li>{v}</li>' for v in vulns)
    scan_time  = asset.get("scan_time", "")[:19].replace("T", " ") + " UTC"

    subdomain_btn = ""
    if subdomain_count > 0:
        subdomain_btn = f"""
      <button class="subdomain-toggle" onclick="toggleSubdomains('{group_id}', this)">
        View {subdomain_count} subdomain{'s' if subdomain_count != 1 else ''} ↓
      </button>"""

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
          <div class="kv">{dot(kex_class)}<span class="k">Key exchange</span><span class="v">{safe(kex,'algorithm')}</span></div>
          <div class="kv">{dot(cert_class)}<span class="k">Certificate</span><span class="v">{safe(cert,'key_type')} ({safe(cert,'key_bits')}-bit)</span></div>
          <div class="kv">{dot(sym_class)}<span class="k">Symmetric</span><span class="v">{safe(conn,'enc_algorithm')}</span></div>
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

      <div class="card-footer-row">
        <span class="card-footer">Scanned {scan_time}</span>
        {subdomain_btn}
      </div>
    </div>"""

# ── Compact subdomain row ──────────────────────────────────────────
def render_subdomain_row(asset):
    label = get_label(asset)
    meta  = LABEL_META.get(label, LABEL_META["ERROR"])
    host  = asset.get("host", "?")
    port  = asset.get("port", 443)

    if label == "ERROR":
        return f"""
        <div class="sub-row sub-row-error" data-label="{label}">
          <span class="sub-host">{host}:{port}</span>
          <span class="label-badge {meta['css']}">{meta['badge']}</span>
          <span class="sub-detail" style="color:var(--text3)">Connection failed</span>
        </div>"""

    conn = asset.get("connection", {})
    kex  = asset.get("key_exchange", {})
    cert = asset.get("certificate", {})

    kex_class  = kex.get("classification", "unknown")
    cert_class = cert.get("classification", "unknown")
    sym_class  = asset.get("symmetric", {}).get("classification", "unknown")

    days = cert.get("days_until_expiry", 9999)
    expiry_class = "expiry-expired" if isinstance(days, int) and days < 0 else \
                   "expiry-soon"    if isinstance(days, int) and days < 30 else ""

    tls     = safe(conn, "tls_version")
    cipher  = safe(conn, "cipher_suite")
    kex_alg = safe(kex, "algorithm")

    return f"""
    <div class="sub-row" data-label="{label}">
      <div class="sub-header">
        <span class="sub-host">{host}<span class="host-port">:{port}</span></span>
        <span class="label-badge {meta['css']}">{meta['badge']}</span>
      </div>
      <div class="sub-details">
        <span class="sub-pill">{tls}</span>
        <span class="sub-pill cipher-text">{cipher}</span>
        <span class="sub-pill">{dot(kex_class)} {kex_alg}</span>
        <span class="sub-pill">{dot(cert_class)} {safe(cert,'key_type')} {safe(cert,'key_bits')}-bit</span>
        <span class="sub-pill">{dot(sym_class)} {safe(conn,'enc_algorithm')}</span>
        <span class="sub-pill {expiry_class}">exp {safe(cert,'not_after', default='?')} ({days}d)</span>
      </div>
    </div>"""

# ── Domain group (root card + optional subdomain drawer) ───────────
def render_domain_group(rd, members, group_idx):
    group_id = f"grp{group_idx}"

    # Separate root from subdomains
    root_asset = next(
        (a for a in members if a.get("host", "").split(":")[0] == rd),
        members[0]
    )
    subs = [a for a in members if a is not root_asset]

    worst = worst_label(members)
    root_card = render_asset_card(root_asset, subdomain_count=len(subs), group_id=group_id)

    if not subs:
        return f'<div class="domain-group" data-label="{worst}" id="{group_id}">{root_card}</div>'

    sub_rows = "\n".join(render_subdomain_row(a) for a in subs)
    return f"""
    <div class="domain-group" data-label="{worst}" id="{group_id}">
      {root_card}
      <div class="subdomain-drawer" id="{group_id}-drawer">
        <div class="subdomain-drawer-header">
          <span>{len(subs)} subdomain{'s' if len(subs) != 1 else ''} of {rd}</span>
          <span class="sub-stats">{_sub_stats_html(subs)}</span>
        </div>
        <div class="subdomain-list">
          {sub_rows}
        </div>
      </div>
    </div>"""

def _sub_stats_html(subs):
    counts = {}
    for a in subs:
        l = get_label(a)
        counts[l] = counts.get(l, 0) + 1
    parts = []
    order = ["FULLY_QUANTUM_SAFE", "PQC_READY", "NOT_PQC_READY", "CRITICAL", "ERROR"]
    symbols = {"FULLY_QUANTUM_SAFE": "✦", "PQC_READY": "◈",
               "NOT_PQC_READY": "◇", "CRITICAL": "✖", "ERROR": "—"}
    css = {"FULLY_QUANTUM_SAFE": "var(--fqs)", "PQC_READY": "var(--pqc)",
           "NOT_PQC_READY": "var(--notpqc)", "CRITICAL": "var(--critical)",
           "ERROR": "var(--text3)"}
    for l in order:
        if counts.get(l):
            parts.append(f'<span style="color:{css[l]}">{symbols[l]} {counts[l]}</span>')
    return " &nbsp; ".join(parts)

# ── Main render ────────────────────────────────────────────────────
def render_html(cbom):
    assets = cbom.get("assets", [])
    stats  = compute_stats(assets)
    total  = len(assets)
    scan_start = cbom.get("scan_start", "")[:19].replace("T", " ")

    groups = group_assets(assets)
    groups_html = "\n".join(
        render_domain_group(rd, members, idx)
        for idx, (rd, members) in enumerate(groups.items())
    )
    n_groups = len(groups)

    fqs_pct  = round(stats["FULLY_QUANTUM_SAFE"] / total * 100) if total else 0
    pqc_pct  = round(stats["PQC_READY"]          / total * 100) if total else 0
    npqc_pct = round(stats["NOT_PQC_READY"]       / total * 100) if total else 0
    crit_pct = round(stats["CRITICAL"]            / total * 100) if total else 0

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

  /* ── Progress bar ── */
  .progress-bar {{ height: 3px; display: flex; background: var(--bg); }}
  .pb-fqs    {{ background: var(--fqs);      width: {fqs_pct}%; }}
  .pb-pqc    {{ background: var(--pqc);      width: {pqc_pct}%; }}
  .pb-notpqc {{ background: var(--notpqc);   width: {npqc_pct}%; }}
  .pb-crit   {{ background: var(--critical); width: {crit_pct}%; }}

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
  .stat-num   {{ font-family: var(--font-head); font-size: 2.2rem; font-weight: 800; line-height: 1; }}
  .stat-label {{ font-size: 0.72rem; color: var(--text3); letter-spacing: 0.08em; text-transform: uppercase; }}
  .stat-pct   {{ font-size: 0.72rem; color: var(--text3); }}
  .stat-fqs   .stat-num {{ color: var(--fqs); }}
  .stat-pqc   .stat-num {{ color: var(--pqc); }}
  .stat-notpqc .stat-num {{ color: var(--notpqc); }}
  .stat-crit  .stat-num {{ color: var(--critical); }}
  .stat-total .stat-num {{ color: #fff; }}

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
  .filter-btn:hover  {{ border-color: var(--accent); color: var(--accent); }}
  .filter-btn.active {{ background: var(--accent); color: #000; border-color: var(--accent); font-weight: 600; }}

  /* ── Main content ── */
  .main {{ padding: 2rem 2.5rem; display: flex; flex-direction: column; gap: 1px; background: var(--border); border: 1px solid var(--border); }}

  /* ── Domain group ── */
  .domain-group {{ display: flex; flex-direction: column; gap: 0; }}

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

  .card-footer-row {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-top: 1rem;
    flex-wrap: wrap;
    gap: 0.5rem;
  }}
  .card-footer {{ font-size: 0.65rem; color: var(--text3); }}
  .error-msg {{ font-size: 0.78rem; color: var(--text3); padding: 0.5rem 0; }}

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
  .label-fqs     {{ background: rgba(0,255,148,0.12); color: var(--fqs);      border: 1px solid rgba(0,255,148,0.3); }}
  .label-pqc     {{ background: rgba(0,207,255,0.12); color: var(--pqc);      border: 1px solid rgba(0,207,255,0.3); }}
  .label-notpqc  {{ background: rgba(245,166,35,0.12); color: var(--notpqc);  border: 1px solid rgba(245,166,35,0.3); }}
  .label-critical{{ background: rgba(255,77,77,0.12);  color: var(--critical);border: 1px solid rgba(255,77,77,0.3); }}
  .label-error   {{ background: rgba(100,100,100,0.1); color: var(--text3);   border: 1px solid var(--border2); }}

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
  .small-text  {{ font-size: 0.65rem; }}

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
  .vuln-block {{ background: rgba(255,77,77,0.06); border-left: 2px solid var(--critical); }}
  .rec-block  {{ background: rgba(0,229,255,0.04); border-left: 2px solid var(--accent); }}
  .vuln-block ul, .rec-block ul {{ padding-left: 1.2rem; }}
  .vuln-block li, .rec-block li {{ margin-bottom: 0.3rem; color: var(--text2); }}
  .vuln-block .section-title {{ color: var(--critical); border-color: rgba(255,77,77,0.2); }}
  .rec-block .section-title  {{ color: var(--accent);   border-color: rgba(0,229,255,0.15); }}

  /* ── Subdomain toggle button ── */
  .subdomain-toggle {{
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    padding: 0.3rem 0.85rem;
    background: rgba(0,229,255,0.07);
    border: 1px solid rgba(0,229,255,0.25);
    border-radius: 2px;
    color: var(--accent);
    font-family: var(--font-mono);
    font-size: 0.72rem;
    cursor: pointer;
    transition: background 0.15s, border-color 0.15s;
    letter-spacing: 0.03em;
  }}
  .subdomain-toggle:hover {{ background: rgba(0,229,255,0.14); border-color: rgba(0,229,255,0.5); }}
  .subdomain-toggle.open  {{ background: rgba(0,229,255,0.14); }}

  /* ── Subdomain drawer ── */
  .subdomain-drawer {{
    display: none;
    flex-direction: column;
    border-top: 1px solid var(--border2);
    background: var(--bg);
  }}
  .subdomain-drawer.open {{ display: flex; }}

  .subdomain-drawer-header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 0.6rem 1.6rem;
    font-size: 0.68rem;
    color: var(--text3);
    border-bottom: 1px solid var(--border);
    flex-wrap: wrap;
    gap: 0.5rem;
  }}
  .sub-stats {{ display: flex; gap: 0.8rem; font-size: 0.68rem; }}

  /* ── Subdomain rows ── */
  .subdomain-list {{ display: flex; flex-direction: column; }}
  .sub-row {{
    display: flex;
    flex-direction: column;
    gap: 0.35rem;
    padding: 0.7rem 1.6rem;
    border-bottom: 1px solid var(--border);
    transition: background 0.12s;
  }}
  .sub-row:last-child {{ border-bottom: none; }}
  .sub-row:hover {{ background: var(--bg2); }}
  .sub-row-error {{ opacity: 0.5; }}

  .sub-header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 1rem;
    flex-wrap: wrap;
  }}
  .sub-host {{
    font-family: var(--font-head);
    font-size: 0.88rem;
    font-weight: 600;
    color: var(--text);
  }}
  .sub-details {{
    display: flex;
    flex-wrap: wrap;
    gap: 0.4rem;
    align-items: center;
  }}
  .sub-pill {{
    font-size: 0.68rem;
    color: var(--text3);
    background: var(--bg3);
    border: 1px solid var(--border);
    padding: 0.1rem 0.5rem;
    border-radius: 2px;
    white-space: nowrap;
    display: inline-flex;
    align-items: center;
    gap: 0.2rem;
  }}

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
    <div>{total} asset(s) across {n_groups} domain(s)</div>
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
  <button class="filter-btn active" onclick="filter('ALL', this)">All ({n_groups})</button>
  <button class="filter-btn" onclick="filter('FULLY_QUANTUM_SAFE', this)">✦ Quantum Safe ({stats['FULLY_QUANTUM_SAFE']})</button>
  <button class="filter-btn" onclick="filter('PQC_READY', this)">◈ PQC Ready ({stats['PQC_READY']})</button>
  <button class="filter-btn" onclick="filter('NOT_PQC_READY', this)">◇ Not PQC Ready ({stats['NOT_PQC_READY']})</button>
  <button class="filter-btn" onclick="filter('CRITICAL', this)">✖ Critical ({stats['CRITICAL']})</button>
</div>

<main class="main" id="assets-grid">
  {groups_html}
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
// Filter operates on domain groups using their worst-label data attribute
function filter(label, btn) {{
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('.domain-group').forEach(grp => {{
    if (label === 'ALL') {{
      grp.classList.remove('hidden');
    }} else {{
      // Show the group if the root card OR any subdomain matches
      const rootLabel = grp.querySelector('.asset-card')?.dataset.label;
      const subLabels = Array.from(grp.querySelectorAll('.sub-row')).map(r => r.dataset.label);
      const match = rootLabel === label || subLabels.includes(label);
      grp.classList.toggle('hidden', !match);
    }}
  }});
}}

function toggleSubdomains(groupId, btn) {{
  const drawer = document.getElementById(groupId + '-drawer');
  const open   = drawer.classList.toggle('open');
  btn.classList.toggle('open', open);
  btn.textContent = open
    ? btn.textContent.replace('↓', '↑').replace('View', 'Hide')
    : btn.textContent.replace('↑', '↓').replace('Hide', 'View');
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
