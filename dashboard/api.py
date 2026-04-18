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


def init(db: Optional[DB]) -> None:
    global _db
    _db = db


def add_alert(a: Alert) -> None:
    with _lock:
        _recent.append(a)


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
    if _db is None:
        return jsonify({"error": "no database"}), 503
    try:
        return jsonify(_db.stats())
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
h1{color:#58a6ff;margin-bottom:1rem}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1.5rem;margin-bottom:1rem}
.stat{font-size:2rem;font-weight:bold;color:#f0883e}
.label{color:#8b949e;font-size:.875rem}
table{width:100%;border-collapse:collapse;margin-top:1rem}
th{color:#8b949e;text-align:left;padding:.5rem;border-bottom:1px solid #30363d}
td{padding:.5rem;border-bottom:1px solid #21262d;font-size:.875rem}
.high{color:#f85149}.med{color:#f0883e}.low{color:#3fb950}
</style>
</head>
<body>
<h1>IntrusionShield — NIDS Dashboard</h1>
<div id="stats" class="card"><p class="label">Loading stats...</p></div>
<div class="card">
<h2>Recent Alerts</h2>
<table><thead><tr><th>Time</th><th>Severity</th><th>Message</th><th>Src</th><th>Dst</th></tr></thead>
<tbody id="alerts"><tr><td colspan="5">Loading...</td></tr></tbody></table>
</div>
<script>
const sev={1:'<span class="low">LOW</span>',2:'<span class="med">MEDIUM</span>',3:'<span class="high">HIGH</span>'};
async function load(){
  try{
    const s=await fetch('/api/stats').then(r=>r.json());
    document.getElementById('stats').innerHTML=
      '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:1rem">'+
      stat('Total Alerts',s.total_alerts)+stat('Last Hour',s.alerts_last_hour)+
      stat('High Severity',s.high_severity)+stat('Pkts/min',s.packets_last_minute)+'</div>';
  }catch(e){document.getElementById('stats').innerHTML='<p class="label">DB unavailable</p>';}
  const a=await fetch('/api/alerts/live').then(r=>r.json());
  document.getElementById('alerts').innerHTML=(a||[]).slice(0,50).map(x=>
    '<tr><td>'+new Date(x.Timestamp).toLocaleTimeString()+'</td><td>'+(sev[x.Severity]||x.Severity)+
    '</td><td>'+x.Msg+'</td><td>'+x.SrcIP+':'+x.SrcPort+'</td><td>'+x.DstIP+':'+x.DstPort+'</td></tr>'
  ).join('')||'<tr><td colspan="5">No alerts yet</td></tr>';
}
function stat(l,v){return'<div><div class="stat">'+(v||0)+'</div><div class="label">'+l+'</div></div>'}
load();setInterval(load,5000);
</script>
</body>
</html>"""
