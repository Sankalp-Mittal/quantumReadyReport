#!/usr/bin/env python3
"""
PQC CBOM Scanner — Web Frontend
Run: python3 app.py
Open: http://localhost:5000
"""

import json
import os
import queue
import subprocess
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path

from flask import Flask, Response, jsonify, render_template_string, request, send_file
from generate_report import render_html as _render_report, load_cbom as _load_cbom

app = Flask(__name__)

SCRIPT_DIR = Path(__file__).parent
OUTPUT_DIR = SCRIPT_DIR / "output"
SCAN_SH    = SCRIPT_DIR / "scan.sh"

# Active scan streams: scan_id → Queue of lines
_streams: dict[str, queue.Queue] = {}

# In-memory report store: report_id → {html, ts, n_hosts, created_at}
_reports: dict[str, dict] = {}

# scan_id → report_id (set when scan finishes, independent of SSE lifetime)
_scan_reports: dict[str, str] = {}

# Reports are evicted after this many seconds (default 1 hour, override via env)
REPORT_TTL = int(os.environ.get("REPORT_TTL", 3600))


def _reap_reports():
    """Background thread: delete reports older than REPORT_TTL every 5 minutes."""
    while True:
        time.sleep(300)
        cutoff = time.monotonic() - REPORT_TTL
        expired = [rid for rid, m in list(_reports.items()) if m["created_at"] < cutoff]
        for rid in expired:
            _reports.pop(rid, None)
        # Also clean up scan→report mappings whose report has been evicted
        for sid in [s for s, r in list(_scan_reports.items()) if r in expired]:
            _scan_reports.pop(sid, None)
        if expired:
            app.logger.info(f"Reaped {len(expired)} expired report(s). {len(_reports)} remaining.")

# ── HTML template ─────────────────────────────────────────────────────────────
TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PQC CBOM Scanner</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=Syne:wght@400;600;800&display=swap" rel="stylesheet">
<style>
  :root {
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
    --font-head: 'Syne', sans-serif;
    --font-mono: 'IBM Plex Mono', monospace;
  }
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  html { font-size: 14px; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--font-mono);
    min-height: 100vh;
    display: grid;
    grid-template-rows: auto 1fr auto;
  }

  /* ── Header ── */
  header {
    border-bottom: 1px solid var(--border);
    padding: 1.8rem 2.5rem 1.4rem;
    display: flex;
    align-items: flex-end;
    justify-content: space-between;
    gap: 1rem;
    flex-wrap: wrap;
  }
  header h1 {
    font-family: var(--font-head);
    font-size: 1.9rem;
    font-weight: 800;
    letter-spacing: -0.03em;
    color: #fff;
  }
  header h1 span { color: var(--accent); }
  .header-sub { font-size: 0.75rem; color: var(--text3); margin-top: 0.25rem; }

  /* ── Layout ── */
  main {
    display: grid;
    grid-template-columns: 380px 1fr;
    gap: 0;
    min-height: 0;
  }
  @media (max-width: 900px) {
    main { grid-template-columns: 1fr; }
  }

  /* ── Scan panel ── */
  .scan-panel {
    border-right: 1px solid var(--border);
    padding: 2rem;
    position: sticky;
    top: 0;
    height: 100vh;
    overflow-y: auto;
    display: flex;
    flex-direction: column;
    gap: 1.4rem;
  }
  .panel-title {
    font-size: 0.65rem;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--text3);
    padding-bottom: 0.6rem;
    border-bottom: 1px solid var(--border);
  }

  label { font-size: 0.78rem; color: var(--text2); display: block; margin-bottom: 0.4rem; }

  textarea, input[type="text"] {
    width: 100%;
    background: var(--bg2);
    border: 1px solid var(--border2);
    border-radius: 2px;
    color: var(--text);
    font-family: var(--font-mono);
    font-size: 0.82rem;
    padding: 0.7rem 0.9rem;
    outline: none;
    resize: vertical;
    transition: border-color 0.15s;
  }
  textarea:focus, input[type="text"]:focus {
    border-color: var(--accent);
  }
  textarea { min-height: 120px; }

  .hint { font-size: 0.68rem; color: var(--text3); margin-top: 0.35rem; }

  .options-row {
    display: flex;
    flex-direction: column;
    gap: 0.6rem;
  }
  .checkbox-row {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.78rem;
    color: var(--text2);
    cursor: pointer;
  }
  .checkbox-row input { accent-color: var(--accent); cursor: pointer; width: 14px; height: 14px; }

  .btn-scan {
    width: 100%;
    padding: 0.75rem 1rem;
    background: var(--accent);
    color: #000;
    font-family: var(--font-head);
    font-size: 0.9rem;
    font-weight: 700;
    letter-spacing: 0.04em;
    border: none;
    border-radius: 2px;
    cursor: pointer;
    transition: opacity 0.15s, transform 0.1s;
  }
  .btn-scan:hover { opacity: 0.85; }
  .btn-scan:active { transform: scale(0.98); }
  .btn-scan:disabled { opacity: 0.35; cursor: not-allowed; }

  /* ── Output panel ── */
  .output-panel {
    padding: 1.5rem 2rem;
    display: flex;
    flex-direction: column;
    gap: 0.8rem;
    height: calc(100vh - 90px); /* viewport minus header */
    min-height: 0;
  }

  .output-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 1rem;
    flex-wrap: wrap;
    flex-shrink: 0;
  }
  .output-title {
    font-size: 0.65rem;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--text3);
  }
  .report-link {
    display: none;
    padding: 0.35rem 0.9rem;
    background: rgba(0,229,255,0.1);
    border: 1px solid rgba(0,229,255,0.3);
    color: var(--accent);
    font-size: 0.75rem;
    text-decoration: none;
    border-radius: 2px;
    transition: background 0.15s;
  }
  .report-link:hover { background: rgba(0,229,255,0.2); }
  .report-link.visible { display: inline-block; }

  /* ── Terminal ── */
  .terminal {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 2px;
    padding: 1.2rem 1.4rem;
    flex: 1 1 0;
    min-height: 0;
    overflow-y: auto;
    font-size: 0.82rem;
    line-height: 1.75;
    white-space: pre-wrap;
    word-break: break-word;
    color: var(--text2);
  }
  .terminal .placeholder { color: var(--text3); font-style: italic; }
  .terminal .line-ok     { color: var(--fqs); }
  .terminal .line-pqc    { color: var(--pqc); }
  .terminal .line-warn   { color: var(--notpqc); }
  .terminal .line-err    { color: var(--critical); }
  .terminal .line-info   { color: var(--accent); }
  .terminal .line-dim    { color: var(--text3); }
  .terminal .line-bold   { color: #fff; font-weight: 600; }
  .terminal .line-sep    { color: var(--accent); opacity: 0.5; }

  .status-bar {
    display: flex;
    align-items: center;
    gap: 0.8rem;
    font-size: 0.72rem;
    color: var(--text3);
    flex-shrink: 0;
    height: 1.8rem;
  }
  .spinner {
    display: none;
    width: 10px; height: 10px;
    border: 2px solid var(--border2);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 0.7s linear infinite;
  }
  .spinner.active { display: inline-block; }
  @keyframes spin { to { transform: rotate(360deg); } }

  /* ── Footer ── */
  footer {
    border-top: 1px solid var(--border);
    padding: 1rem 2.5rem;
    font-size: 0.68rem;
    color: var(--text3);
    display: flex;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 0.5rem;
  }
</style>
</head>
<body>

<header>
  <div>
    <h1>PQC <span>CBOM</span> Scanner</h1>
    <div class="header-sub">Cryptographic Bill of Materials — Quantum Readiness Assessment</div>
  </div>
  <div style="font-size:0.72rem;color:var(--text3);text-align:right;">
    PNB Cybersecurity Hackathon 2025-26
  </div>
</header>

<main>
  <!-- ── Left: Scan Input ── -->
  <aside class="scan-panel">
    <div>
      <div class="panel-title">New Scan</div>
    </div>

    <div>
      <label for="hosts">Hosts to scan</label>
      <textarea id="hosts" placeholder="google.com&#10;cloudflare.com&#10;api.example.com:8443"></textarea>
      <div class="hint">One host per line. Use host:port for custom ports.</div>
    </div>

    <div class="options-row">
      <div class="panel-title">Options</div>
      <label class="checkbox-row">
        <input type="checkbox" id="opt-subdomains">
        Discover subdomains (Warning: This might take a lot of time to run)
      </label>
      <label class="checkbox-row">
        <input type="checkbox" id="opt-json">
        JSON output only (no terminal colour)
      </label>
    </div>

    <button class="btn-scan" id="btn-scan" onclick="startScan()">
      Run Scan
    </button>

  </aside>

  <!-- ── Right: Output ── -->
  <section class="output-panel">
    <div class="output-header">
      <div class="output-title">Terminal Output</div>
      <a href="#" class="report-link" id="report-link">View HTML Report →</a>
    </div>

    <div class="terminal" id="terminal">
      <span class="placeholder">Enter hosts and press Run Scan to begin...</span>
    </div>

    <div class="status-bar">
      <div class="spinner" id="spinner"></div>
      <span id="status-text">Idle</span>
    </div>
  </section>
</main>

<footer>
  <div>PQC CBOM Scanner v1.0.0 — scan.sh + generate_report.py</div>
  <div>Output directory: {{ output_dir }}</div>
</footer>

<script>
let evtSource = null;

function ansiToHtml(line) {
  // Strip all ANSI escape codes
  const clean = line.replace(/\x1b\\[[0-9;]*m/g, '').replace(/\x1b\\[[0-9;]*[A-Za-z]/g, '');
  if (!clean.trim()) return '<span class="line-dim">&nbsp;</span>';

  const e = esc(clean);

  // Separators / box-drawing
  if (/═{4,}/.test(clean))                           return `<span class="line-sep">${e}</span>`;
  // Labels
  if (/FULLY.QUANTUM.SAFE|✦/.test(clean))            return `<span class="line-ok">${e}</span>`;
  if (/◈.*PQC.READY/.test(clean) && !/NOT/.test(clean)) return `<span class="line-pqc">${e}</span>`;
  if (/NOT.PQC.READY|◇/.test(clean))                 return `<span class="line-warn">${e}</span>`;
  if (/CRITICAL|✖/.test(clean))                      return `<span class="line-err">${e}</span>`;
  // Progress / status
  if (/connection failed|Could not connect|✘/.test(clean)) return `<span class="line-err">${e}</span>`;
  if (/[\u25b8] Scanning|subfinder|Discovering/.test(clean))   return `<span class="line-dim">${e}</span>`;
  if (/SUMMARY|CBOM saved|Report generated/.test(clean))        return `<span class="line-bold">${e}</span>`;
  if (/Scanning [0-9]+|host.s./.test(clean))                     return `<span class="line-dim">${e}</span>`;
  // Section headers inside host report
  if (/^(Connection|Quantum Analysis|Certificate Details|Recommendations)$/.test(clean.trim()))
                                                         return `<span class="line-bold">${e}</span>`;
  // Quantum dot lines
  if (/Key exchange.*→|Certificate.*→|Data encrypt.*→/.test(clean)) return `<span>${e}</span>`;
  // Dimmed detail lines
  if (/^ *(Subject|Issuer|Expires|Chain|TLS version|Cipher suite|Cert verify) *:/.test(clean))
                                                     return `<span class="line-dim">${e}</span>`;
  return `<span>${e}</span>`;
}

function esc(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function startScan() {
  const hostsRaw = document.getElementById('hosts').value.trim();
  if (!hostsRaw) { alert('Enter at least one host.'); return; }

  const hosts      = hostsRaw.split('\\n').map(h => h.trim()).filter(Boolean);
  const subdomains = document.getElementById('opt-subdomains').checked;
  const jsonOnly   = document.getElementById('opt-json').checked;

  // Reset UI
  const term = document.getElementById('terminal');
  term.innerHTML = '';
  document.getElementById('report-link').classList.remove('visible');
  document.getElementById('btn-scan').disabled = true;
  document.getElementById('spinner').classList.add('active');
  document.getElementById('status-text').textContent = 'Starting scan…';

  if (evtSource) { evtSource.close(); evtSource = null; }

  // POST to /scan → get scan_id, then open SSE stream
  fetch('/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ hosts, subdomains, json_only: jsonOnly })
  })
  .then(r => r.json())
  .then(data => {
    if (data.error) throw new Error(data.error);
    openStream(data.scan_id);
  })
  .catch(err => {
    appendLine(term, `<span class="line-err">Error: ${esc(err.message)}</span>`);
    resetUI('Error');
  });
}

function openStream(scanId) {
  const term = document.getElementById('terminal');
  document.getElementById('status-text').textContent = 'Scanning…';

  evtSource = new EventSource(`/stream/${scanId}`);

  evtSource.addEventListener('line', e => {
    appendLine(term, ansiToHtml(e.data));
  });

  evtSource.addEventListener('report', e => {
    const link = document.getElementById('report-link');
    link.href = `/view/${e.data}`;
    link.classList.add('visible');
  });

  evtSource.addEventListener('done', e => {
    evtSource.close();
    const summary = JSON.parse(e.data || '{}');
    resetUI(`Done — ${summary.hosts || ''} host(s) scanned`);
    if (!document.getElementById('report-link').classList.contains('visible')) {
      pollReport(scanId);
    }
  });

  evtSource.onerror = () => {
    evtSource.close();
    resetUI('Scan running — waiting for report…');
    pollReport(scanId);
  };
}

function pollReport(scanId) {
  const interval = setInterval(() => {
    fetch(`/report-ready/${scanId}`)
      .then(r => r.json())
      .then(data => {
        if (data.report_id) {
          clearInterval(interval);
          const link = document.getElementById('report-link');
          link.href = `/view/${data.report_id}`;
          link.classList.add('visible');
          resetUI('Done — report ready');
        }
      })
      .catch(() => clearInterval(interval));
  }, 5000);
}

function appendLine(term, html) {
  const span = document.createElement('span');
  span.innerHTML = html + '\\n';
  term.appendChild(span);
  term.scrollTop = term.scrollHeight;
}

function resetUI(msg) {
  document.getElementById('btn-scan').disabled = false;
  document.getElementById('spinner').classList.remove('active');
  document.getElementById('status-text').textContent = msg;
}


</script>
</body>
</html>"""


# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template_string(TEMPLATE, output_dir=str(OUTPUT_DIR))


def _build_report_nav() -> str:
    """Sticky nav bar injected into every in-memory report."""
    return """<div id="report-nav">
  <a href="/" id="rn-back">← New Scan</a>
  <span id="rn-title">PQC CBOM Report</span>
  <button id="rn-download" onclick="downloadReport()">Download HTML ↓</button>
</div>
<style>
  #report-nav {
    position: sticky; top: 0; z-index: 999;
    background: rgba(10,12,16,0.96); backdrop-filter: blur(10px);
    border-bottom: 1px solid #1e2430;
    padding: 0.6rem 2rem;
    display: flex; align-items: center; justify-content: space-between; gap: 1rem;
    font-family: 'IBM Plex Mono', monospace; font-size: 0.75rem;
  }
  #rn-back { color: #00e5ff; text-decoration: none; }
  #rn-back:hover { text-decoration: underline; }
  #rn-title { color: #4a5266; font-size: 0.68rem; }
  #rn-download {
    padding: 0.28rem 0.85rem;
    background: rgba(0,229,255,0.08); border: 1px solid rgba(0,229,255,0.3);
    color: #00e5ff; font-family: inherit; font-size: 0.72rem;
    cursor: pointer; border-radius: 2px; transition: background 0.15s;
  }
  #rn-download:hover { background: rgba(0,229,255,0.18); }
</style>
<script>
function downloadReport() {
  const clone = document.documentElement.cloneNode(true);
  // Remove the nav bar from the downloaded copy so it's self-contained
  clone.querySelector('#report-nav')?.remove();
  const html = '<!DOCTYPE html>\\n' + clone.outerHTML;
  const blob = new Blob([html], {type: 'text/html'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'pqc_report.html';
  document.body.appendChild(a); a.click();
  document.body.removeChild(a); URL.revokeObjectURL(a.href);
}
</script>"""


@app.route("/scan", methods=["POST"])
def scan():
    data       = request.get_json(force=True)
    hosts      = data.get("hosts", [])
    subdomains = data.get("subdomains", False)
    json_only  = data.get("json_only", False)

    if not hosts:
        return jsonify({"error": "No hosts provided"}), 400

    scan_id = str(uuid.uuid4())
    q: queue.Queue = queue.Queue()
    _streams[scan_id] = q

    def run():
        cmd = ["bash", str(SCAN_SH)] + hosts
        if subdomains:
            cmd.append("--subdomains")
        if json_only:
            cmd.append("--json")

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            for line in proc.stdout:
                q.put(("line", line.rstrip("\n")))
            proc.wait()
        except Exception as exc:
            q.put(("line", f"Error running scan: {exc}"))

        # Generate report in memory from the latest CBOM JSON
        report_id = None
        try:
            cbom_files = sorted(
                OUTPUT_DIR.glob("cbom_*.json"),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            if cbom_files:
                cbom = _load_cbom(str(cbom_files[0]))
                cbom["_source"] = cbom_files[0].name
                html = _render_report(cbom)
                # Inject nav bar right after <body>
                html = html.replace("<body>", "<body>\n" + _build_report_nav(), 1)
                report_id = str(uuid.uuid4())
                _reports[report_id] = {
                    "html":       html,
                    "ts":         datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
                    "n_hosts":    len(cbom.get("assets", [])),
                    "created_at": time.monotonic(),
                }
        except Exception as exc:
            q.put(("line", f"[report] Could not generate report: {exc}"))

        if report_id:
            _scan_reports[scan_id] = report_id
            q.put(("report", report_id))
        q.put(("done", {"hosts": len(hosts)}))

    threading.Thread(target=run, daemon=True).start()
    return jsonify({"scan_id": scan_id})


@app.route("/stream/<scan_id>")
def stream(scan_id):
    q = _streams.get(scan_id)
    if q is None:
        return Response("data: unknown scan_id\n\n", mimetype="text/event-stream")

    def generate():
        import json as _json
        import time
        deadline = time.monotonic() + 7200  # 2-hour hard cap
        while True:
            if time.monotonic() > deadline:
                yield "event: done\ndata: {}\n\n"
                break
            try:
                event, payload = q.get(timeout=5)
            except queue.Empty:
                # Send a keepalive SSE comment so the browser doesn't close the connection
                yield ": keepalive\n\n"
                continue

            if event == "line":
                safe_payload = payload.replace("\n", "\\n")
                yield f"event: line\ndata: {safe_payload}\n\n"
            elif event == "report":
                yield f"event: report\ndata: {payload}\n\n"
            elif event == "done":
                yield f"event: done\ndata: {_json.dumps(payload)}\n\n"
                break

        _streams.pop(scan_id, None)

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/report-ready/<scan_id>")
def report_ready(scan_id):
    rid = _scan_reports.get(scan_id)
    if rid:
        return jsonify({"report_id": rid})
    return jsonify({"report_id": None})


@app.route("/view/<report_id>")
def view_report(report_id):
    meta = _reports.get(report_id)
    if not meta:
        return "Report not found (server may have restarted — run a new scan).", 404
    return Response(meta["html"], mimetype="text/html")


# ── Start background reaper ───────────────────────────────────────────────────
threading.Thread(target=_reap_reports, daemon=True, name="report-reaper").start()

# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print("PQC CBOM Scanner — Web Frontend")
    print(f"  Output dir : {OUTPUT_DIR}")
    print(f"  Scan script: {SCAN_SH}")
    print(f"  Listening  : http://0.0.0.0:{port}")
    print()
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
