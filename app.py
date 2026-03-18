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

app = Flask(__name__)

SCRIPT_DIR = Path(__file__).parent
OUTPUT_DIR = SCRIPT_DIR / "output"
SCAN_SH    = SCRIPT_DIR / "scan.sh"

# Active scan streams: scan_id → Queue of lines (None = done)
_streams: dict[str, queue.Queue] = {}

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

  /* ── Past scans ── */
  .past-scans { display: flex; flex-direction: column; gap: 0.4rem; }
  .past-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 0.5rem;
    padding: 0.5rem 0.7rem;
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 2px;
    font-size: 0.72rem;
    flex-wrap: wrap;
  }
  .past-item a { color: var(--accent); text-decoration: none; }
  .past-item a:hover { text-decoration: underline; }
  .past-item .ts { color: var(--text3); font-size: 0.65rem; }
  .no-scans { font-size: 0.75rem; color: var(--text3); }

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
        Discover subdomains (subfinder)
      </label>
      <label class="checkbox-row">
        <input type="checkbox" id="opt-report" checked>
        Generate HTML report
      </label>
      <label class="checkbox-row">
        <input type="checkbox" id="opt-json">
        Save JSON only (no terminal output)
      </label>
    </div>

    <button class="btn-scan" id="btn-scan" onclick="startScan()">
      Run Scan
    </button>

    <div>
      <div class="panel-title" style="margin-bottom:0.8rem;">Past Reports</div>
      <div class="past-scans" id="past-scans">
        {{ past_scans_html | safe }}
      </div>
    </div>
  </aside>

  <!-- ── Right: Output ── -->
  <section class="output-panel">
    <div class="output-header">
      <div class="output-title">Terminal Output</div>
      <a href="#" class="report-link" id="report-link" target="_blank">View HTML Report →</a>
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
  const report     = document.getElementById('opt-report').checked;
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
    body: JSON.stringify({ hosts, subdomains, report, json_only: jsonOnly })
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
    link.href = `/report/${e.data}`;
    link.classList.add('visible');
  });

  evtSource.addEventListener('done', e => {
    evtSource.close();
    const summary = JSON.parse(e.data || '{}');
    resetUI(`Done — ${summary.hosts || ''} host(s) scanned`);
    refreshPastScans();
  });

  evtSource.onerror = () => {
    evtSource.close();
    resetUI('Stream disconnected');
  };
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

function refreshPastScans() {
  fetch('/past-scans')
    .then(r => r.text())
    .then(html => { document.getElementById('past-scans').innerHTML = html; });
}
</script>
</body>
</html>"""

# ── Past scans HTML helper ────────────────────────────────────────────────────
def past_scans_html():
    items = []
    if OUTPUT_DIR.exists():
        reports = sorted(OUTPUT_DIR.glob("pqc_report_*.html"), reverse=True)[:10]
        cboms   = {p.stem.replace("pqc_report_","cbom_"): p for p in reports}
        for rpt in reports:
            ts_raw = rpt.stem.replace("pqc_report_","")
            try:
                ts = datetime.strptime(ts_raw, "%Y%m%d_%H%M%S").strftime("%Y-%m-%d %H:%M")
            except Exception:
                ts = ts_raw
            cbom_name = "cbom_" + ts_raw + ".json"
            items.append(
                f'<div class="past-item">'
                f'<a href="/report/{rpt.name}" target="_blank">Report {ts}</a>'
                f'<span class="ts"><a href="/cbom/{cbom_name}" style="color:var(--text3)">JSON</a></span>'
                f'</div>'
            )
    if not items:
        return '<div class="no-scans">No reports yet.</div>'
    return "\n".join(items)


# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template_string(
        TEMPLATE,
        past_scans_html=past_scans_html(),
        output_dir=str(OUTPUT_DIR),
    )


@app.route("/past-scans")
def past_scans_route():
    return past_scans_html()


@app.route("/scan", methods=["POST"])
def scan():
    data       = request.get_json(force=True)
    hosts      = data.get("hosts", [])
    subdomains = data.get("subdomains", False)
    report     = data.get("report", True)
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
        if report:
            cmd.append("--report")
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

        # Find the most recently generated report
        report_file = None
        if report and OUTPUT_DIR.exists():
            reports = sorted(OUTPUT_DIR.glob("pqc_report_*.html"), key=lambda p: p.stat().st_mtime, reverse=True)
            if reports:
                report_file = reports[0].name

        if report_file:
            q.put(("report", report_file))
        q.put(("done", {"hosts": len(hosts), "report": report_file}))

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
        deadline = time.monotonic() + 600  # 10-minute hard cap
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


@app.route("/report/<filename>")
def serve_report(filename):
    path = OUTPUT_DIR / filename
    if not path.exists() or path.suffix != ".html":
        return "Not found", 404
    return send_file(path, mimetype="text/html")


@app.route("/cbom/<filename>")
def serve_cbom(filename):
    path = OUTPUT_DIR / filename
    if not path.exists() or path.suffix != ".json":
        return "Not found", 404
    return send_file(path, mimetype="application/json")


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print("PQC CBOM Scanner — Web Frontend")
    print(f"  Output dir : {OUTPUT_DIR}")
    print(f"  Scan script: {SCAN_SH}")
    print(f"  Listening  : http://0.0.0.0:{port}")
    print()
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
