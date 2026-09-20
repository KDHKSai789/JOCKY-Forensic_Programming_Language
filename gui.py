"""
JOCKY Forensic GUI - Local web dashboard.
Launch with: jocky gui
"""

import json
import os
import sys
import threading
import webbrowser
import errno
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

from compiler.compiler import Compiler, CompilationError
from runtime.executor import JockyRuntime, JockyRuntimeError


_latest_result: dict = {}
_server: HTTPServer | None = None
PORT = 7890


# ============================================================
# HTML Template
# ============================================================

def _html_page(body: str, title: str = "JOCKY Forensic Dashboard") -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&family=JetBrains+Mono:wght@400;600&display=swap');
  :root {{
    --bg:#0a0e1a; --surface:#111827; --surface2:#1e2a3a;
    --accent:#00d4ff; --accent2:#7c3aed; --danger:#ef4444;
    --warn:#f59e0b; --success:#10b981; --text:#e2e8f0;
    --muted:#64748b; --border:#1e3a5f;
  }}
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:var(--bg);color:var(--text);font-family:'Inter',sans-serif;min-height:100vh}}
  header{{background:linear-gradient(135deg,#0a1628 0%,#111827 100%);border-bottom:1px solid var(--border);
    padding:1rem 2rem;display:flex;align-items:center;gap:1rem}}
  header h1{{font-size:1.3rem;font-weight:700;background:linear-gradient(90deg,var(--accent),var(--accent2));
    -webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}}
  header span{{font-size:.75rem;color:var(--muted);font-family:'JetBrains Mono',monospace}}
  nav{{display:flex;gap:.5rem;padding:1rem 2rem;background:var(--surface);border-bottom:1px solid var(--border);flex-wrap:wrap}}
  nav a{{color:var(--muted);text-decoration:none;padding:.4rem .9rem;border-radius:.4rem;font-size:.85rem;
    transition:all .2s;border:1px solid transparent}}
  nav a:hover,nav a.active{{color:var(--accent);border-color:var(--accent);background:rgba(0,212,255,.08)}}
  main{{padding:1.5rem 2rem;max-width:1400px}}
  .card{{background:var(--surface);border:1px solid var(--border);border-radius:.75rem;padding:1.25rem;margin-bottom:1rem}}
  .card h2{{font-size:.95rem;font-weight:600;color:var(--accent);margin-bottom:.75rem;text-transform:uppercase;letter-spacing:.05em}}
  .badge{{display:inline-block;padding:.2rem .6rem;border-radius:.3rem;font-size:.75rem;font-weight:600;font-family:'JetBrains Mono',monospace}}
  .badge.high{{background:#7f1d1d;color:#fca5a5}} .badge.medium{{background:#78350f;color:#fde68a}}
  .badge.low{{background:#064e3b;color:#6ee7b7}} .badge.ok{{background:#064e3b;color:#6ee7b7}}
  .badge.info{{background:#1e3a5f;color:var(--accent)}}
  table{{width:100%;border-collapse:collapse;font-size:.82rem}}
  th{{color:var(--muted);font-weight:600;text-align:left;padding:.5rem .75rem;border-bottom:1px solid var(--border);
    text-transform:uppercase;font-size:.72rem;letter-spacing:.05em}}
  td{{padding:.5rem .75rem;border-bottom:1px solid rgba(30,58,95,.4);vertical-align:top}}
  tr:hover td{{background:rgba(0,212,255,.04)}}
  code{{font-family:'JetBrains Mono',monospace;font-size:.8rem;color:var(--accent);word-break:break-all}}
  .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:1rem;margin-bottom:1rem}}
  .stat{{background:var(--surface2);border:1px solid var(--border);border-radius:.6rem;padding:1rem;text-align:center}}
  .stat .val{{font-size:2rem;font-weight:700;color:var(--accent)}}
  .stat .lbl{{font-size:.75rem;color:var(--muted);margin-top:.25rem}}
  .risk-bar{{height:8px;border-radius:4px;background:var(--surface2);overflow:hidden;margin:.5rem 0}}
  .risk-fill{{height:100%;border-radius:4px;background:linear-gradient(90deg,var(--success),var(--warn),var(--danger))}}
  form{{display:flex;flex-direction:column;gap:.75rem}}
  textarea{{background:var(--surface2);border:1px solid var(--border);color:var(--text);
    border-radius:.5rem;padding:.75rem;font-family:'JetBrains Mono',monospace;font-size:.82rem;
    resize:vertical;min-height:280px;outline:none}}
  textarea:focus{{border-color:var(--accent)}}
  button{{background:linear-gradient(135deg,var(--accent2),#4f46e5);color:#fff;border:none;
    border-radius:.5rem;padding:.65rem 1.5rem;font-size:.9rem;font-weight:600;cursor:pointer;
    transition:all .2s;align-self:flex-start}}
  button:hover{{transform:translateY(-1px);box-shadow:0 4px 15px rgba(124,58,237,.4)}}
  .alert{{padding:.75rem 1rem;border-radius:.5rem;margin-bottom:.75rem;font-size:.85rem}}
  .alert.error{{background:#7f1d1d;border:1px solid #ef4444;color:#fca5a5}}
  .alert.success{{background:#064e3b;border:1px solid #10b981;color:#6ee7b7}}
  pre{{background:var(--surface2);border:1px solid var(--border);border-radius:.5rem;
    padding:1rem;overflow:auto;font-family:'JetBrains Mono',monospace;font-size:.78rem;max-height:400px}}
  .explanation{{color:var(--muted);font-size:.78rem;font-style:italic;margin-top:.25rem}}
</style>
</head>
<body>
<header>
  <span style="font-size:1.5rem">🔬</span>
  <div>
    <h1>JOCKY Forensic Dashboard</h1>
    <span>Linux Forensic Analysis Framework v1.3.0</span>
  </div>
</header>
<nav>
  <a href="/" id="nav-home">Dashboard</a>
  <a href="/run" id="nav-run">Run Investigation</a>
  <a href="/results" id="nav-results">Results</a>
  <a href="/timeline" id="nav-timeline">Timeline</a>
  <a href="/evidence" id="nav-evidence">Evidence</a>
  <a href="/correlation" id="nav-correlation">Correlation</a>
  <a href="/report" id="nav-report">Report</a>
</nav>
<main>{body}</main>
<script>
  const path = window.location.pathname;
  document.querySelectorAll('nav a').forEach(a => {{
    if(a.getAttribute('href') === path) a.classList.add('active');
  }});
</script>
</body>
</html>"""


# ============================================================
# Page Renderers
# ============================================================

def _page_dashboard() -> str:
    r = _latest_result
    if not r:
        body = """
<div class="card">
  <h2>Welcome to JOCKY</h2>
  <p style="color:var(--muted);margin-bottom:1rem">No investigation has been run yet.</p>
  <a href="/run" style="color:var(--accent)">→ Start an investigation</a>
</div>"""
        return _html_page(body)

    ctx = r.get("context", {})
    risk = ctx.get("risk", {})
    score = risk.get("risk_score", 0)
    level = risk.get("risk_level", "UNKNOWN")
    badge_cls = "high" if level in ("HIGH","CRITICAL") else "medium" if level == "MEDIUM" else "low"
    collections = ctx.get("collected_data", {})
    analyses = ctx.get("analysis_results", {})
    correlations = ctx.get("correlations", [])
    timeline = ctx.get("timeline", [])
    evidence = {k:v for k,v in ctx.get("evidence",{}).items() if k != "_verification"}

    findings_total = sum(
        a.get("finding_count", 0)
        for a in analyses.values()
        if isinstance(a, dict) and not a.get("variable")
    )

    body = f"""
<div class="grid">
  <div class="stat"><div class="val">{len(collections)}</div><div class="lbl">Sources Collected</div></div>
  <div class="stat"><div class="val">{len(analyses)}</div><div class="lbl">Analyses Run</div></div>
  <div class="stat"><div class="val">{findings_total}</div><div class="lbl">Total Findings</div></div>
  <div class="stat"><div class="val">{len(correlations)}</div><div class="lbl">Correlations</div></div>
  <div class="stat"><div class="val">{len(timeline)}</div><div class="lbl">Timeline Events</div></div>
  <div class="stat"><div class="val">{len(evidence)}</div><div class="lbl">Evidence Records</div></div>
</div>
<div class="card">
  <h2>Risk Assessment</h2>
  <p>Score: <span class="badge {badge_cls}">{score}/100 — {level}</span></p>
  <div class="risk-bar"><div class="risk-fill" style="width:{min(score,100)}%"></div></div>
  <p style="color:var(--muted);font-size:.82rem;margin-top:.5rem">
    Case: <code>{ctx.get('case_name','—')}</code> | Target: <code>{ctx.get('target','—')}</code>
  </p>
</div>
<div class="card">
  <h2>Collected Sources</h2>
  <table><tr><th>Source</th><th>Status</th><th>Records</th></tr>"""
    for src, item in collections.items():
        status = item.get("status", "complete")
        count = (item.get("process_count") or item.get("connection_count") or
                 item.get("file_count") or item.get("driver_count") or
                 item.get("event_count") or item.get("binary_count") or "—")
        body += f"<tr><td><code>{src}</code></td><td><span class='badge ok'>{status}</span></td><td>{count}</td></tr>"
    body += "</table></div>"
    return _html_page(body)


def _page_run(msg: str = "", msg_type: str = "") -> str:
    sample = '''CASE "MyInvestigation"
TARGET "LOCAL"
COLLECT processes
COLLECT network.connections
COLLECT filesystem.recent
COLLECT memory.indicators
ANALYZE processes
LET process_review_candidates = ANALYZE processes WHERE threads > 20 AND pid > 100
ANALYZE network.connections
CORRELATE processes WITH network.connections
TIMELINE
VERIFY evidence
REPORT "investigation_report.json"'''

    alert = f'<div class="alert {msg_type}">{msg}</div>' if msg else ""
    body = f"""
<div class="card">
  <h2>Run a JOCKY Investigation</h2>
  {alert}
  <form method="POST" action="/run">
    <label style="color:var(--muted);font-size:.85rem">Paste or type your JOCKY script below:</label>
    <textarea name="script" placeholder="CASE &quot;MyCase&quot;&#10;TARGET &quot;LOCAL&quot;&#10;COLLECT processes&#10;...">{sample}</textarea>
    <button type="submit" id="run-btn">▶ Run Investigation</button>
  </form>
</div>"""
    return _html_page(body, "Run Investigation - JOCKY")


def _page_results() -> str:
    r = _latest_result
    if not r:
        return _html_page('<div class="card"><h2>No Results</h2><p style="color:var(--muted)">Run an investigation first.</p></div>')

    ctx = r.get("context", {})
    analyses = ctx.get("analysis_results", {})
    body = "<div class='card'><h2>Analysis Results</h2>"

    for name, result in analyses.items():
        if not isinstance(result, dict):
            continue
        count = result.get("finding_count", 0)
        severity = result.get("severity_counts") or result.get("severity", {})
        is_candidate_set = bool(result.get("variable"))
        body += f"<p style='margin:.5rem 0'><code>{name}</code> — {count} findings "
        if is_candidate_set:
            body += "<span class='badge info'>TRIAGE CANDIDATES</span> "
        for sev, n in severity.items():
            if n:
                body += f"<span class='badge {sev}'>{n} {sev}</span> "
        body += "</p>"
        if is_candidate_set:
            body += "<p class='explanation'>A LET filter identifies records for analyst review; it does not independently confirm malicious activity or affect the risk score.</p>"
        findings = result.get("findings", [])[:10]
        if findings:
            body += "<table><tr><th>Rule / Type</th><th>Description</th><th>Severity</th></tr>"
            for f in findings:
                sev = f.get("severity","info")
                rule_name = f.get("rule") or f.get("type") or f.get("category") or "—"
                body += f"<tr><td><code>{rule_name}</code></td><td>{f.get('description','')}</td><td><span class='badge {sev}'>{sev}</span></td></tr>"
            body += "</table>"

    body += "</div>"
    return _html_page(body, "Results - JOCKY")


def _page_timeline() -> str:
    r = _latest_result
    if not r:
        return _html_page('<div class="card"><h2>No Timeline</h2><p style="color:var(--muted)">Run an investigation first.</p></div>')

    events = r.get("context", {}).get("timeline", [])
    body = f"<div class='card'><h2>Forensic Timeline ({len(events)} events)</h2>"
    if events:
        body += "<table><tr><th>Timestamp</th><th>Source</th><th>Type</th><th>Description</th></tr>"
        for ev in events[:200]:
            ts = str(ev.get("timestamp",""))[:19]
            body += f"<tr><td><code>{ts}</code></td><td>{ev.get('source','')}</td><td><span class='badge info'>{ev.get('event_type','')}</span></td><td>{ev.get('description','')}</td></tr>"
        body += "</table>"
    else:
        body += "<p style='color:var(--muted)'>No timeline events.</p>"
    body += "</div>"
    return _html_page(body, "Timeline - JOCKY")


def _page_evidence() -> str:
    r = _latest_result
    if not r:
        return _html_page('<div class="card"><h2>No Evidence</h2><p style="color:var(--muted)">Run an investigation first.</p></div>')

    ctx = r.get("context", {})
    evidence = {k:v for k,v in ctx.get("evidence",{}).items() if k != "_verification"}
    verification = ctx.get("evidence", {}).get("_verification", {})

    body = f"<div class='card'><h2>Evidence Integrity ({len(evidence)} records)</h2>"
    body += "<table><tr><th>Evidence ID</th><th>Source</th><th>SHA-256</th><th>Integrity</th></tr>"
    for eid, ev in evidence.items():
        rec = ev.get("record", {})
        ver = verification.get(eid, {})
        intact = ver.get("verified", ver.get("intact", None))
        badge = "ok" if intact else "high" if intact is False else "info"
        label = "VERIFIED" if intact else "TAMPERED" if intact is False else "UNCHECKED"
        sha = rec.get("sha256", "—")[:32] + "..."
        body += f"<tr><td><code>{eid}</code></td><td>{rec.get('source','—')}</td><td><code>{sha}</code></td><td><span class='badge {badge}'>{label}</span></td></tr>"
    body += "</table></div>"
    return _html_page(body, "Evidence - JOCKY")


def _page_correlation() -> str:
    r = _latest_result
    if not r:
        return _html_page('<div class="card"><h2>No Correlation Data</h2><p style="color:var(--muted)">Run an investigation first.</p></div>')

    correlations = r.get("context", {}).get("correlations", [])
    body = f"<div class='card'><h2>Correlation Analysis ({len(correlations)} correlations)</h2>"
    for corr in correlations:
        ctype = corr.get("type", "unknown")
        status = corr.get("status", "—")
        explanation = corr.get("explanation", "")
        matches = corr.get("matches", corr.get("processes", corr.get("overlaps", [])))
        count = corr.get("match_count", corr.get("correlated_connection_count", len(matches) if isinstance(matches, list) else 0))
        body += f"<div class='card' style='margin-top:.5rem'>"
        body += f"<h2>{ctype.replace('_',' ').title()}</h2>"
        body += f"<p style='color:var(--muted);font-size:.82rem;margin-bottom:.5rem'>{explanation}</p>"
        body += f"<p><span class='badge info'>{status}</span> &nbsp; {count} matches</p>"
        if isinstance(matches, list) and matches:
            body += "<table style='margin-top:.5rem'><tr>"
            keys = [k for k in matches[0].keys() if k not in ("connections","explanation","matches")]
            for k in keys[:5]:
                body += f"<th>{k}</th>"
            body += "</tr>"
            for m in matches[:15]:
                body += "<tr>"
                for k in keys[:5]:
                    val = m.get(k, "—")
                    body += f"<td><code>{str(val)[:60]}</code></td>"
                body += "</tr>"
            body += "</table>"
        body += "</div>"
    body += "</div>"
    return _html_page(body, "Correlation - JOCKY")


def _page_report() -> str:
    r = _latest_result
    if not r:
        return _html_page('<div class="card"><h2>No Report</h2><p style="color:var(--muted)">Run an investigation first.</p></div>')

    ctx = r.get("context", {})
    report = ctx.get("report", {})
    if not report:
        return _html_page('<div class="card"><h2>No Report Generated</h2><p style="color:var(--muted)">Include REPORT filename.json in your script.</p></div>')

    out_file = report.get("output_file", "—")
    body = f"""
<div class="card">
  <h2>Forensic Report</h2>
  <p style="color:var(--muted);margin-bottom:.75rem">Report file: <code>{out_file}</code></p>
  <p><a href="/download_report" style="color:var(--accent)">⬇ Download JSON Report</a></p>
</div>
<div class="card">
  <h2>Report Preview</h2>
  <pre>{json.dumps(report, indent=2, default=str)[:8000]}</pre>
</div>"""
    return _html_page(body, "Report - JOCKY")


# ============================================================
# HTTP Handler
# ============================================================

class JockyHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        pass  # Suppress default access logs

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        routes = {
            "/": _page_dashboard,
            "/run": _page_run,
            "/results": _page_results,
            "/timeline": _page_timeline,
            "/evidence": _page_evidence,
            "/correlation": _page_correlation,
            "/report": _page_report,
        }

        if path == "/download_report":
            r = _latest_result
            report = r.get("context", {}).get("report", {}) if r else {}
            payload = json.dumps(report, indent=2, default=str).encode("utf-8")
            self._send(200, "application/json", payload)
            return

        if path in routes:
            html = routes[path]()
            self._send(200, "text/html", html.encode("utf-8"))
        else:
            self._send(404, "text/html", b"<h1>Not Found</h1>")

    def do_POST(self):
        global _latest_result
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/run":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            qs = parse_qs(body)
            script = qs.get("script", [""])[0]

            if not script.strip():
                html = _page_run("Script cannot be empty.", "error")
                self._send(200, "text/html", html.encode("utf-8"))
                return

            try:
                compiler = Compiler()
                ir = compiler.compile_str(script)
                runtime = JockyRuntime()
                context = runtime.execute(ir)
                _latest_result = {"context": context.__dict__ if hasattr(context, "__dict__") else {}}
                # Store full context object for GUI access
                _latest_result["context_obj"] = context
                _latest_result["context"] = {
                    "case_name": context.case_name,
                    "target": context.target,
                    "collected_data": context.collected_data,
                    "analysis_results": context.analysis_results,
                    "variables": {k: {kk:vv for kk,vv in v.items() if kk != "data"} for k,v in context.variables.items()},
                    "correlations": context.correlations,
                    "risk": context.risk,
                    "timeline": context.timeline,
                    "evidence": context.evidence,
                    "report": context.report,
                }
                self._redirect("/")
            except CompilationError as e:
                html = _page_run(f"Compilation error: {e}", "error")
                self._send(200, "text/html", html.encode("utf-8"))
            except JockyRuntimeError as e:
                html = _page_run(f"Runtime error: {e}", "error")
                self._send(200, "text/html", html.encode("utf-8"))
            except Exception as e:
                html = _page_run(f"Error: {e}", "error")
                self._send(200, "text/html", html.encode("utf-8"))
        else:
            self._send(404, "text/html", b"Not Found")

    def _send(self, code: int, content_type: str, body: bytes):
        self.send_response(code)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, location: str):
        self.send_response(302)
        self.send_header("Location", location)
        self.end_headers()


# ============================================================
# Compile from string support
# ============================================================

# ============================================================
# Entry Point
# ============================================================

def start_gui(port: int = PORT):
    global _server
    try:
        _server = HTTPServer(("127.0.0.1", port), JockyHandler)
    except OSError as error:
        if error.errno != errno.EADDRINUSE:
            raise
        _server = HTTPServer(("127.0.0.1", 0), JockyHandler)
        port = _server.server_address[1]
        print(f"Port {PORT} is already in use; using local port {port}.")
    url = f"http://127.0.0.1:{port}"

    print("=" * 60)
    print("      JOCKY FORENSIC DASHBOARD")
    print("=" * 60)
    print(f"\n  Dashboard: {url}")
    print("  Press Ctrl+C to stop.\n")

    def _open():
        import time
        time.sleep(0.5)
        webbrowser.open(url)

    threading.Thread(target=_open, daemon=True).start()

    try:
        _server.serve_forever()
    except KeyboardInterrupt:
        print("\n[JOCKY GUI] Shutting down.")
        _server.shutdown()


if __name__ == "__main__":
    start_gui()
