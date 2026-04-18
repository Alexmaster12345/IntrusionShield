package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"

	"github.com/Alexmaster12345/IntrusionShield/detection"
	"github.com/Alexmaster12345/IntrusionShield/storage"
)

// Server serves the REST API and the embedded Grafana config.
type Server struct {
	db      *storage.DB
	recent  *recentAlerts
	router  *mux.Router
	httpSrv *http.Server
}

// recentAlerts is an in-memory ring buffer of the last N alerts.
type recentAlerts struct {
	buf  []detection.Alert
	size int
	idx  int
}

func newRecentAlerts(size int) *recentAlerts { return &recentAlerts{buf: make([]detection.Alert, 0, size), size: size} }

func (r *recentAlerts) add(a detection.Alert) {
	if len(r.buf) < r.size {
		r.buf = append(r.buf, a)
	} else {
		r.buf[r.idx%r.size] = a
		r.idx++
	}
}

func (r *recentAlerts) all() []detection.Alert { return r.buf }

// NewServer creates the API server.
func NewServer(db *storage.DB, port int) *Server {
	s := &Server{
		db:     db,
		recent: newRecentAlerts(500),
		router: mux.NewRouter(),
	}
	s.httpSrv = &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      s.router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	s.registerRoutes()
	return s
}

// AddAlert adds a live alert to the in-memory buffer.
func (s *Server) AddAlert(a detection.Alert) { s.recent.add(a) }

// Start begins serving.
func (s *Server) Start() {
	log.Printf("[dashboard] API listening on %s", s.httpSrv.Addr)
	go func() {
		if err := s.httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[dashboard] server error: %v", err)
		}
	}()
}

// Stop gracefully shuts down.
func (s *Server) Stop(ctx context.Context) { _ = s.httpSrv.Shutdown(ctx) }

func (s *Server) registerRoutes() {
	r := s.router
	r.Use(corsMiddleware)

	r.HandleFunc("/api/health", s.handleHealth).Methods("GET")
	r.HandleFunc("/api/stats", s.handleStats).Methods("GET")
	r.HandleFunc("/api/alerts", s.handleAlerts).Methods("GET")
	r.HandleFunc("/api/alerts/live", s.handleLiveAlerts).Methods("GET")
	r.PathPrefix("/").HandlerFunc(s.handleStatic)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]string{"status": "ok", "time": time.Now().Format(time.RFC3339)})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.db.Stats(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, stats)
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	n := 100
	if nStr := r.URL.Query().Get("limit"); nStr != "" {
		if parsed, err := strconv.Atoi(nStr); err == nil && parsed > 0 {
			n = parsed
		}
	}
	alerts, err := s.db.RecentAlerts(r.Context(), n)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, alerts)
}

func (s *Server) handleLiveAlerts(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.recent.all())
}

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" || r.URL.Path == "/index.html" {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, indexHTML)
		return
	}
	http.NotFound(w, r)
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// indexHTML is a minimal status page embedded in the binary.
const indexHTML = `<!DOCTYPE html>
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
  const s=await fetch('/api/stats').then(r=>r.json());
  document.getElementById('stats').innerHTML=
    '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:1rem">'+
    stat('Total Alerts',s.total_alerts)+stat('Last Hour',s.alerts_last_hour)+
    stat('High Severity',s.high_severity)+stat('Pkts/min',s.packets_last_minute)+'</div>';
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
</html>`
