from __future__ import annotations
import logging
import threading
from collections import deque, defaultdict
from dataclasses import asdict
from datetime import datetime, timedelta
from typing import Deque, Dict, List, Optional
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
# timeline: list of (timestamp, severity) for last 5 min
_timeline: Deque = deque(maxlen=3000)
# top sources: src_ip -> count
_top_sources: Dict[str, int] = defaultdict(int)
# protocol counts
_proto_counts: Dict[str, int] = defaultdict(int)


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
        _timeline.append((a.timestamp, a.severity))
        if a.src_ip:
            _top_sources[a.src_ip] += 1
        if a.protocol:
            _proto_counts[a.protocol.upper()] += 1


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


@app.route("/api/timeline")
def timeline():
    """Alerts bucketed by 5-second intervals for the last 2 minutes."""
    now = datetime.utcnow()
    buckets: Dict[int, Dict[str, int]] = {}
    for i in range(24):
        buckets[i] = {"high": 0, "med": 0, "low": 0}

    with _lock:
        items = list(_timeline)

    cutoff = now - timedelta(minutes=2)
    for ts, sev in items:
        if ts < cutoff:
            continue
        age = (now - ts).total_seconds()
        idx = min(23, int(age / 5))
        bucket_idx = 23 - idx
        if sev == 3:
            buckets[bucket_idx]["high"] += 1
        elif sev == 2:
            buckets[bucket_idx]["med"] += 1
        else:
            buckets[bucket_idx]["low"] += 1

    labels = [f"-{(23-i)*5}s" if (23-i)*5 > 0 else "now" for i in range(24)]
    return jsonify({
        "labels": labels,
        "high": [buckets[i]["high"] for i in range(24)],
        "med":  [buckets[i]["med"]  for i in range(24)],
        "low":  [buckets[i]["low"]  for i in range(24)],
    })


@app.route("/api/top-sources")
def top_sources():
    with _lock:
        sources = dict(_top_sources)
    top = sorted(sources.items(), key=lambda x: x[1], reverse=True)[:10]
    return jsonify([{"ip": ip, "count": count} for ip, count in top])


@app.route("/api/protocols")
def protocols():
    with _lock:
        counts = dict(_proto_counts)
    return jsonify(counts)


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
<title>IntrusionShield — NIDS</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
:root{
  --bg:#0d1117;--surface:#161b22;--border:#30363d;--border2:#21262d;
  --text:#e6edf3;--muted:#8b949e;--primary:#58a6ff;
  --green:#3fb950;--orange:#f0883e;--red:#f85149;--purple:#bc8cff;
}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;display:flex;min-height:100vh}

/* ── Sidebar ── */
.sidebar{width:220px;background:var(--surface);border-right:1px solid var(--border);
  display:flex;flex-direction:column;padding:1.25rem 0;flex-shrink:0;position:fixed;height:100vh;z-index:10}
.logo{padding:0 1.25rem 1.5rem;border-bottom:1px solid var(--border);margin-bottom:.75rem}
.logo-title{font-size:1.1rem;font-weight:700;color:var(--primary);letter-spacing:.5px}
.logo-sub{font-size:.72rem;color:var(--muted);margin-top:.1rem}
.nav-item{display:flex;align-items:center;gap:.6rem;padding:.55rem 1.25rem;font-size:.875rem;
  color:var(--muted);cursor:pointer;transition:all .15s;border-left:2px solid transparent}
.nav-item:hover{color:var(--text);background:rgba(88,166,255,.06)}
.nav-item.active{color:var(--primary);background:rgba(88,166,255,.1);border-left-color:var(--primary)}
.nav-icon{font-size:1rem;width:1.2rem;text-align:center}
.sidebar-footer{margin-top:auto;padding:1rem 1.25rem;border-top:1px solid var(--border)}
.live-dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--green);
  margin-right:.4rem;animation:pulse 1.4s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.25}}

/* ── Main ── */
.main{margin-left:220px;flex:1;padding:1.75rem;overflow-y:auto}
.page{display:none}.page.active{display:block}
.page-header{margin-bottom:1.5rem}
.page-title{font-size:1.3rem;font-weight:600;color:var(--text)}
.page-sub{font-size:.82rem;color:var(--muted);margin-top:.2rem}

/* ── Stat cards ── */
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin-bottom:1.5rem}
.card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:1.1rem 1.25rem;position:relative;overflow:hidden}
.card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px}
.card.blue::before{background:linear-gradient(90deg,var(--primary),transparent)}
.card.orange::before{background:linear-gradient(90deg,var(--orange),transparent)}
.card.red::before{background:linear-gradient(90deg,var(--red),transparent)}
.card.green::before{background:linear-gradient(90deg,var(--green),transparent)}
.card-icon{font-size:1.4rem;margin-bottom:.5rem;opacity:.85}
.card-val{font-size:1.9rem;font-weight:700;line-height:1;margin-bottom:.3rem}
.card.blue .card-val{color:var(--primary)}
.card.orange .card-val{color:var(--orange)}
.card.red .card-val{color:var(--red)}
.card.green .card-val{color:var(--green)}
.card-label{font-size:.78rem;color:var(--muted)}

/* ── Charts row ── */
.charts-row{display:grid;grid-template-columns:1fr 320px;gap:1rem;margin-bottom:1.5rem}
.chart-card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:1.1rem 1.25rem}
.chart-title{font-size:.875rem;font-weight:600;color:var(--text);margin-bottom:1rem}
.chart-wrap{position:relative;height:180px}

/* ── Table ── */
.table-card{background:var(--surface);border:1px solid var(--border);border-radius:10px;overflow:hidden}
.table-header{padding:.9rem 1.25rem;border-bottom:1px solid var(--border);
  display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.5rem}
.table-title{font-size:.875rem;font-weight:600}
.controls{display:flex;gap:.5rem;align-items:center}
.search{background:var(--bg);border:1px solid var(--border);border-radius:6px;
  color:var(--text);padding:.35rem .7rem;font-size:.8rem;outline:none;width:200px}
.search:focus{border-color:var(--primary)}
.filter-btn{background:var(--bg);border:1px solid var(--border);border-radius:6px;
  color:var(--muted);padding:.35rem .7rem;font-size:.78rem;cursor:pointer;transition:all .15s}
.filter-btn:hover,.filter-btn.active{background:rgba(88,166,255,.1);color:var(--primary);border-color:var(--primary)}
.filter-btn.sev3.active{background:rgba(248,81,73,.1);color:var(--red);border-color:var(--red)}
.filter-btn.sev2.active{background:rgba(240,136,62,.1);color:var(--orange);border-color:var(--orange)}
.filter-btn.sev1.active{background:rgba(63,185,80,.1);color:var(--green);border-color:var(--green)}
table{width:100%;border-collapse:collapse}
th{color:var(--muted);font-size:.74rem;text-transform:uppercase;letter-spacing:.5px;
  padding:.55rem 1rem;border-bottom:1px solid var(--border);text-align:left;font-weight:500}
td{padding:.55rem 1rem;border-bottom:1px solid var(--border2);font-size:.83rem;vertical-align:middle}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(255,255,255,.02)}
.badge{display:inline-flex;align-items:center;gap:.3rem;padding:.18rem .55rem;
  border-radius:4px;font-size:.72rem;font-weight:600;letter-spacing:.3px}
.badge-high{background:#2d1b1b;color:var(--red);border:1px solid rgba(248,81,73,.25)}
.badge-med{background:#2d2210;color:var(--orange);border:1px solid rgba(240,136,62,.25)}
.badge-low{background:#0d2117;color:var(--green);border:1px solid rgba(63,185,80,.25)}
.ip{font-family:"SF Mono",Consolas,monospace;font-size:.8rem}
.port{color:var(--muted)}
.proto-tag{background:rgba(188,140,255,.1);color:var(--purple);border:1px solid rgba(188,140,255,.2);
  font-size:.72rem;padding:.1rem .4rem;border-radius:3px;font-family:monospace}
.empty{color:var(--muted);text-align:center;padding:2.5rem;font-size:.875rem}

/* ── Top sources page ── */
.sources-grid{display:grid;grid-template-columns:1fr 1fr;gap:1rem}
.bar-row{display:flex;align-items:center;gap:.75rem;margin-bottom:.65rem}
.bar-ip{font-family:monospace;font-size:.82rem;width:140px;flex-shrink:0;color:var(--text)}
.bar-track{flex:1;background:var(--border2);border-radius:3px;height:8px;overflow:hidden}
.bar-fill{height:100%;background:linear-gradient(90deg,var(--primary),var(--purple));border-radius:3px;transition:width .4s}
.bar-count{font-size:.8rem;color:var(--muted);width:40px;text-align:right;flex-shrink:0}

/* ── Scrollbar ── */
::-webkit-scrollbar{width:6px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
</style>
</head>
<body>

<!-- Sidebar -->
<aside class="sidebar">
  <div class="logo">
    <div class="logo-title">⚡ IntrusionShield</div>
    <div class="logo-sub">Network Intrusion Detection</div>
  </div>
  <nav>
    <div class="nav-item active" onclick="nav('overview')"><span class="nav-icon">📊</span>Overview</div>
    <div class="nav-item" onclick="nav('alerts')"><span class="nav-icon">🚨</span>Alerts</div>
    <div class="nav-item" onclick="nav('sources')"><span class="nav-icon">🌐</span>Top Sources</div>
  </nav>
  <div class="sidebar-footer">
    <span class="live-dot"></span><span style="font-size:.78rem;color:var(--muted)">Live · 3s refresh</span>
  </div>
</aside>

<!-- Main -->
<main class="main">

  <!-- Overview -->
  <div class="page active" id="page-overview">
    <div class="page-header">
      <div class="page-title">Overview</div>
      <div class="page-sub" id="last-update">Loading…</div>
    </div>
    <div class="cards">
      <div class="card blue"><div class="card-icon">📦</div><div class="card-val" id="s-pkts">—</div><div class="card-label">Packets Captured</div></div>
      <div class="card orange"><div class="card-icon">🚨</div><div class="card-val" id="s-alerts">—</div><div class="card-label">Total Alerts</div></div>
      <div class="card red"><div class="card-icon">🔴</div><div class="card-val" id="s-high">—</div><div class="card-label">High Severity</div></div>
      <div class="card green"><div class="card-icon">🕐</div><div class="card-val" id="s-hour">—</div><div class="card-label">Alerts Last Hour</div></div>
    </div>
    <div class="charts-row">
      <div class="chart-card">
        <div class="chart-title">Alert Timeline — last 2 minutes</div>
        <div class="chart-wrap"><canvas id="timelineChart"></canvas></div>
      </div>
      <div class="chart-card">
        <div class="chart-title">Protocol Distribution</div>
        <div class="chart-wrap"><canvas id="protoChart"></canvas></div>
      </div>
    </div>
    <div class="table-card">
      <div class="table-header">
        <span class="table-title">Recent Alerts</span>
        <span style="font-size:.78rem;color:var(--muted)" id="alert-count">0 alerts</span>
      </div>
      <table>
        <thead><tr><th>Time</th><th>Severity</th><th>Rule</th><th>Source</th><th>Destination</th><th>Proto</th></tr></thead>
        <tbody id="overview-alerts"><tr><td colspan="6" class="empty">Waiting for traffic…</td></tr></tbody>
      </table>
    </div>
  </div>

  <!-- Alerts page -->
  <div class="page" id="page-alerts">
    <div class="page-header">
      <div class="page-title">All Alerts</div>
      <div class="page-sub">Filterable live alert feed</div>
    </div>
    <div class="table-card">
      <div class="table-header">
        <span class="table-title">Alerts</span>
        <div class="controls">
          <input class="search" id="alert-search" placeholder="Search rule, IP…" oninput="renderAlerts()">
          <button class="filter-btn sev3" id="f3" onclick="toggleFilter(3)">HIGH</button>
          <button class="filter-btn sev2" id="f2" onclick="toggleFilter(2)">MEDIUM</button>
          <button class="filter-btn sev1" id="f1" onclick="toggleFilter(1)">LOW</button>
        </div>
      </div>
      <table>
        <thead><tr><th>Time</th><th>Severity</th><th>Rule</th><th>Source</th><th>Destination</th><th>Proto</th></tr></thead>
        <tbody id="alerts-tbody"><tr><td colspan="6" class="empty">Waiting for traffic…</td></tr></tbody>
      </table>
    </div>
  </div>

  <!-- Top Sources page -->
  <div class="page" id="page-sources">
    <div class="page-header">
      <div class="page-title">Top Sources</div>
      <div class="page-sub">Source IPs ranked by alert count</div>
    </div>
    <div class="sources-grid">
      <div class="chart-card" style="grid-column:1/-1">
        <div class="chart-title">Top 10 Alert Sources</div>
        <div id="sources-bars"></div>
      </div>
      <div class="chart-card" style="grid-column:1/-1">
        <div class="chart-title">Severity Breakdown</div>
        <div class="chart-wrap" style="height:220px"><canvas id="sevChart"></canvas></div>
      </div>
    </div>
  </div>

</main>

<script>
// ── State ──
let allAlerts = [];
let activeFilters = new Set();
let timelineChart, protoChart, sevChart;

// ── Navigation ──
function nav(page) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById('page-' + page).classList.add('active');
  event.currentTarget.classList.add('active');
}

// ── Filter ──
function toggleFilter(sev) {
  const btn = document.getElementById('f' + sev);
  if (activeFilters.has(sev)) { activeFilters.delete(sev); btn.classList.remove('active'); }
  else { activeFilters.add(sev); btn.classList.add('active'); }
  renderAlerts();
}

function filteredAlerts() {
  let a = allAlerts;
  if (activeFilters.size) a = a.filter(x => activeFilters.has(x.Severity));
  const q = (document.getElementById('alert-search')?.value || '').toLowerCase();
  if (q) a = a.filter(x =>
    x.Msg.toLowerCase().includes(q) ||
    x.SrcIP.includes(q) || x.DstIP.includes(q) || x.Protocol.toLowerCase().includes(q)
  );
  return a;
}

// ── Render helpers ──
const badge = {
  1: '<span class="badge badge-low">LOW</span>',
  2: '<span class="badge badge-med">MED</span>',
  3: '<span class="badge badge-high">HIGH</span>'
};

function rowHTML(x) {
  const t = new Date(x.Timestamp);
  const time = t.toLocaleTimeString('en-GB', {hour12:false}) + '.' + String(t.getMilliseconds()).padStart(3,'0');
  return `<tr>
    <td style="color:var(--muted);font-family:monospace;font-size:.78rem">${time}</td>
    <td>${badge[x.Severity] || x.Severity}</td>
    <td>${x.Msg}</td>
    <td class="ip">${x.SrcIP}<span class="port">:${x.SrcPort}</span></td>
    <td class="ip">${x.DstIP}<span class="port">:${x.DstPort}</span></td>
    <td><span class="proto-tag">${x.Protocol}</span></td>
  </tr>`;
}

function renderAlerts() {
  const fa = filteredAlerts();
  const html = fa.length ? fa.slice(0,100).map(rowHTML).join('') : '<tr><td colspan="6" class="empty">No matching alerts</td></tr>';
  const ob = document.getElementById('alerts-tbody');
  if (ob) ob.innerHTML = html;
}

function fmt(n) {
  if (n == null) return '—';
  return n >= 1e6 ? (n/1e6).toFixed(1)+'M' : n >= 1e3 ? (n/1e3).toFixed(1)+'K' : n;
}

// ── Charts init ──
Chart.defaults.color = '#8b949e';
Chart.defaults.borderColor = '#30363d';

function initCharts() {
  const tCtx = document.getElementById('timelineChart').getContext('2d');
  timelineChart = new Chart(tCtx, {
    type: 'bar',
    data: { labels: [], datasets: [
      { label: 'High',   data: [], backgroundColor: 'rgba(248,81,73,.7)',   borderRadius: 2 },
      { label: 'Medium', data: [], backgroundColor: 'rgba(240,136,62,.7)',  borderRadius: 2 },
      { label: 'Low',    data: [], backgroundColor: 'rgba(63,185,80,.5)',   borderRadius: 2 },
    ]},
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { position: 'bottom', labels: { boxWidth: 10, font: { size: 11 } } } },
      scales: {
        x: { stacked: true, ticks: { font: { size: 10 }, maxRotation: 0, autoSkip: true, maxTicksLimit: 8 } },
        y: { stacked: true, ticks: { font: { size: 10 }, stepSize: 1 }, beginAtZero: true },
      },
    },
  });

  const pCtx = document.getElementById('protoChart').getContext('2d');
  protoChart = new Chart(pCtx, {
    type: 'doughnut',
    data: { labels: [], datasets: [{ data: [],
      backgroundColor: ['rgba(88,166,255,.8)','rgba(63,185,80,.8)','rgba(240,136,62,.8)',
                         'rgba(248,81,73,.8)','rgba(188,140,255,.8)','rgba(255,235,100,.8)'],
      borderWidth: 0, hoverOffset: 6 }]},
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { position: 'bottom', labels: { boxWidth: 10, font: { size: 11 }, padding: 10 } } },
      cutout: '62%',
    },
  });

  const sCtx = document.getElementById('sevChart').getContext('2d');
  sevChart = new Chart(sCtx, {
    type: 'doughnut',
    data: { labels: ['High', 'Medium', 'Low'], datasets: [{ data: [0, 0, 0],
      backgroundColor: ['rgba(248,81,73,.8)','rgba(240,136,62,.8)','rgba(63,185,80,.7)'],
      borderWidth: 0, hoverOffset: 6 }]},
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { position: 'right', labels: { boxWidth: 12, font: { size: 12 }, padding: 14 } } },
      cutout: '55%',
    },
  });
}

// ── Data fetch & update ──
async function load() {
  try {
    // Stats
    const s = await fetch('/api/stats').then(r => r.json());
    document.getElementById('s-pkts').textContent   = fmt(s.packets_captured);
    document.getElementById('s-alerts').textContent = fmt(s.total_alerts);
    document.getElementById('s-high').textContent   = fmt(s.high_severity || 0);
    document.getElementById('s-hour').textContent   = fmt(s.alerts_last_hour || 0);
    document.getElementById('last-update').textContent =
      'Last updated ' + new Date().toLocaleTimeString();
  } catch(e) {}

  try {
    // Live alerts
    const a = await fetch('/api/alerts/live').then(r => r.json());
    allAlerts = a || [];
    document.getElementById('alert-count').textContent = allAlerts.length + ' alerts';
    // Overview table (last 10)
    const oh = allAlerts.slice(0, 10).map(rowHTML).join('') ||
               '<tr><td colspan="6" class="empty">No alerts yet</td></tr>';
    document.getElementById('overview-alerts').innerHTML = oh;
    renderAlerts();
    // Severity chart
    const h = allAlerts.filter(x=>x.Severity===3).length;
    const m = allAlerts.filter(x=>x.Severity===2).length;
    const l = allAlerts.filter(x=>x.Severity===1).length;
    if (sevChart) { sevChart.data.datasets[0].data = [h, m, l]; sevChart.update('none'); }
  } catch(e) {}

  try {
    // Timeline
    const t = await fetch('/api/timeline').then(r => r.json());
    if (timelineChart) {
      timelineChart.data.labels = t.labels;
      timelineChart.data.datasets[0].data = t.high;
      timelineChart.data.datasets[1].data = t.med;
      timelineChart.data.datasets[2].data = t.low;
      timelineChart.update('none');
    }
  } catch(e) {}

  try {
    // Protocol chart
    const p = await fetch('/api/protocols').then(r => r.json());
    if (protoChart && Object.keys(p).length) {
      protoChart.data.labels = Object.keys(p);
      protoChart.data.datasets[0].data = Object.values(p);
      protoChart.update('none');
    }
  } catch(e) {}

  try {
    // Top sources bars
    const src = await fetch('/api/top-sources').then(r => r.json());
    if (src.length) {
      const max = src[0].count;
      document.getElementById('sources-bars').innerHTML = src.map(s =>
        `<div class="bar-row">
          <div class="bar-ip">${s.ip}</div>
          <div class="bar-track"><div class="bar-fill" style="width:${(s.count/max*100).toFixed(1)}%"></div></div>
          <div class="bar-count">${s.count}</div>
        </div>`
      ).join('');
    }
  } catch(e) {}
}

initCharts();
load();
setInterval(load, 3000);
</script>
</body>
</html>"""
