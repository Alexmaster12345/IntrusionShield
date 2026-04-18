from __future__ import annotations
import json
import logging
import threading
from collections import deque
from dataclasses import asdict
from datetime import datetime
from typing import Deque, Optional
from wsgiref.simple_server import make_server, WSGIServer
from socketserver import ThreadingMixIn

from flask import Flask, jsonify, request, Response

from detection.engine import Alert
from storage.db import DB

logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

_db: Optional[DB] = None
_recent: Deque[Alert] = deque(maxlen=500)
_lock = threading.Lock()
_total_packets = 0
_total_alerts = 0


def init(db: Optional[DB]) -> None:
    global _db
    _db = db


def inc_packets() -> None:
    global _total_packets
    _total_packets += 1


def add_alert(a: Alert) -> None:
    global _total_alerts
    with _lock:
        _recent.append(a)
        _total_alerts += 1



@app.after_request
def cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return response


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "time": datetime.utcnow().isoformat()})


@app.route("/api/stats")
def stats():
    live = {"total_alerts": _total_alerts, "packets_captured": _total_packets}
    if _db is None:
        live.update({"alerts_last_hour": 0, "high_severity": 0, "packets_last_minute": 0})
        return jsonify(live)
    try:
        data = _db.stats()
        data.update(live)
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/alerts")
def alerts():
    if _db is None:
        return jsonify([])
    limit = int(request.args.get("limit", 100))
    try:
        rows = _db.recent_alerts(limit)
        return jsonify([asdict(r) for r in rows])
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/alerts/live")
def live_alerts():
    with _lock:
        items = list(_recent)
    return jsonify([
        {
            "Timestamp": a.timestamp.isoformat(),
            "Msg": a.msg,
            "Severity": a.severity,
            "Protocol": a.protocol,
            "SrcIP": a.src_ip,
            "DstIP": a.dst_ip,
            "SrcPort": a.src_port,
            "DstPort": a.dst_port,
        }
        for a in reversed(items)
    ])


@app.route("/")
@app.route("/index.html")
def index():
    return Response(_INDEX_HTML, mimetype="text/html")


class _ThreadedWSGI(ThreadingMixIn, WSGIServer):
    daemon_threads = True


class Server:
    def __init__(self, db: Optional[DB], port: int):
        init(db)
        self._port = port
        self._server: Optional[_ThreadedWSGI] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self._server = make_server("0.0.0.0", self._port, app, server_class=_ThreadedWSGI)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        logger.info("Dashboard API listening on port %d", self._port)

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()


_INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IntrusionShield</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0d1117;color:#e6edf3;font-family:system-ui,sans-serif;padding:2rem}
h1{color:#58a6ff;margin-bottom:.25rem;font-size:1.6rem}
.subtitle{color:#8b949e;font-size:.85rem;margin-bottom:1.25rem}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin-bottom:1rem}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1.25rem}
.stat{font-size:2rem;font-weight:700;color:#f0883e}
.stat.green{color:#3fb950}.stat.red{color:#f85149}.stat.blue{color:#58a6ff}
.label{color:#8b949e;font-size:.8rem;margin-top:.2rem}
.section{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1.25rem}
.section h2{font-size:1rem;color:#e6edf3;margin-bottom:.75rem}
table{width:100%;border-collapse:collapse}
th{color:#8b949e;text-align:left;padding:.4rem .6rem;border-bottom:1px solid #30363d;font-size:.78rem;text-transform:uppercase}
td{padding:.45rem .6rem;border-bottom:1px solid #21262d;font-size:.85rem}
tr:last-child td{border-bottom:none}
.high{color:#f85149;font-weight:600}.med{color:#f0883e;font-weight:600}.low{color:#3fb950}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:#3fb950;margin-right:.4rem;animation:pulse 1.5s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
.badge{display:inline-block;padding:.15rem .5rem;border-radius:4px;font-size:.75rem}
.badge-high{background:#2d1b1b;color:#f85149;border:1px solid #f8514940}
.badge-med{background:#2d2210;color:#f0883e;border:1px solid #f0883e40}
.badge-low{background:#0d2117;color:#3fb950;border:1px solid #3fb95040}
</style>
</head>
<body>
<h1>⚡ IntrusionShield</h1>
<p class="subtitle"><span class="dot"></span>Live Network Intrusion Detection &nbsp;·&nbsp; refreshes every 3s</p>
<div class="grid" id="stats">
  <div class="card"><div class="stat blue" id="s-pkts">—</div><div class="label">Packets Captured</div></div>
  <div class="card"><div class="stat" id="s-alerts">—</div><div class="label">Total Alerts</div></div>
  <div class="card"><div class="stat red" id="s-high">—</div><div class="label">High Severity</div></div>
  <div class="card"><div class="stat green" id="s-hour">—</div><div class="label">Alerts Last Hour</div></div>
</div>
<div class="section">
  <h2>Recent Alerts <span style="color:#8b949e;font-weight:normal;font-size:.8rem">(live, last 50)</span></h2>
  <table>
    <thead><tr><th>Time</th><th>Severity</th><th>Message</th><th>Source</th><th>Destination</th><th>Proto</th></tr></thead>
    <tbody id="alerts"><tr><td colspan="6" style="color:#8b949e;padding:1rem">Waiting for alerts…</td></tr></tbody>
  </table>
</div>
<script>
const badge={1:'<span class="badge badge-low">LOW</span>',2:'<span class="badge badge-med">MEDIUM</span>',3:'<span class="badge badge-high">HIGH</span>'};
async function load(){
  try{
    const s=await fetch('/api/stats').then(r=>r.json());
    document.getElementById('s-pkts').textContent=fmt(s.packets_captured);
    document.getElementById('s-alerts').textContent=fmt(s.total_alerts);
    document.getElementById('s-high').textContent=fmt(s.high_severity);
    document.getElementById('s-hour').textContent=fmt(s.alerts_last_hour);
  }catch(e){}
  try{
    const a=await fetch('/api/alerts/live').then(r=>r.json());
    document.getElementById('alerts').innerHTML=(a||[]).slice(0,50).map(x=>
      `<tr>
        <td style="color:#8b949e">${new Date(x.Timestamp).toLocaleTimeString()}</td>
        <td>${badge[x.Severity]||x.Severity}</td>
        <td>${x.Msg}</td>
        <td>${x.SrcIP}<span style="color:#8b949e">:${x.SrcPort}</span></td>
        <td>${x.DstIP}<span style="color:#8b949e">:${x.DstPort}</span></td>
        <td style="color:#8b949e">${x.Protocol}</td>
      </tr>`
    ).join('')||'<tr><td colspan="6" style="color:#8b949e;padding:1rem">No alerts yet</td></tr>';
  }catch(e){}
}
function fmt(n){if(n==null)return'—';return n>=1e6?(n/1e6).toFixed(1)+'M':n>=1e3?(n/1e3).toFixed(1)+'K':n}
load();setInterval(load,3000);
</script>
</body>
</html>"""
