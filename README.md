# IntrusionShield

A high-performance Network Intrusion Detection System (NIDS) written in Go.

```
 ___     _                    _            ____  _     _      _     _
|_ _|_ _| |_ _ _ _  _ _____ (_)___ _ _   / ___|| |__ (_) ___| | __| |
 | || ' \  _| '_| || (_-< \ / / _ \ ' \  \___ \| '_ \| |/ _ \ |/ _' |
|___|_||_\__|_|  \_,_/__/\_V /\___/_||_| |____/|_| |_|_|\___/_|\__,_|
                                                   Network IDS v1.0.0
```

## Features

### Packet Capture Engine
- Live capture from any network interface using `libpcap`
- BPF filter support (custom or auto-built from port/protocol lists)
- Saves captured packets to `.pcap` file for offline analysis
- Promiscuous mode support

### Protocol Parser
- Full layer decomposition: Ethernet → IPv4/IPv6 → TCP/UDP/ICMP
- DNS query/response parsing (A, AAAA, CNAME, MX, TXT)
- HTTP/1.x layer-7 best-effort parse (method, host, path, status)
- ICMPv4 and ICMPv6 type/code extraction

### Signature-Based Detection
- 16 built-in signatures covering:
  - Port scans (SYN, NULL, XMAS)
  - Brute force (SSH, FTP, RDP)
  - Protocol anomalies (Telnet, SMB/EternalBlue)
  - Injection attacks (SQLi, XSS, shell injection)
  - Reverse shells (`bash -i`, `nc -e`)
  - DNS tunneling (TXT query patterns)
- Snort-compatible rules file parser
- Per-rule: protocol, CIDR src/dst, port ranges, TCP flags, payload content match (with `nocase`)
- Severity levels: 1=LOW, 2=MEDIUM, 3=HIGH

### Anomaly Detection
- Rolling window statistics (mean + standard deviation over configurable window)
- Z-score based packet rate anomaly detection
- Port scan heuristic: flags source IPs contacting 20+ distinct ports in 10 seconds
- Configurable threshold (default Z ≥ 3.0)

### Storage (PostgreSQL)
- Automatic schema migration on startup
- Stores: alerts, anomaly events, packet metadata summaries
- Indexed by timestamp for fast dashboard queries

### Alerting Channels
| Channel  | Config Key              |
|----------|-------------------------|
| Slack    | `slack_webhook`         |
| Email    | `email_smtp/from/to`    |
| Webhook  | `webhook_url`           |
| Telegram | `telegram_token/chat_id`|

### Dashboard
- Built-in REST API at `http://localhost:8080`
- Endpoints: `/api/health`, `/api/stats`, `/api/alerts`, `/api/alerts/live`
- Embedded HTML status page with auto-refresh every 5 seconds
- Grafana-ready via PostgreSQL datasource

## Quick Start

### Prerequisites
- Go ≥ 1.22
- libpcap (`libpcap-devel` on RHEL/Fedora, `libpcap-dev` on Debian/Ubuntu)
- Root/CAP_NET_RAW for live capture

### Build

```bash
git clone https://github.com/Alexmaster12345/IntrusionShield.git
cd IntrusionShield
go mod download
CGO_ENABLED=1 go build -o intrusion-shield .
```

### Run (CLI sniffer mode)

```bash
sudo ./intrusion-shield -iface eth0 -verbose
```

### Run with config

```bash
cp config.example.json config.json
# Edit interface, DB URL, alert webhooks
sudo ./intrusion-shield -config config.json
```

### Docker Compose (full stack)

```bash
docker compose up -d
```

Starts:
- IntrusionShield NIDS
- PostgreSQL 16 (alerts + packet DB)
- Grafana (pre-wired to PostgreSQL, `http://localhost:3000`)

## Configuration

`config.json` (all fields optional, sensible defaults apply):

```json
{
  "interface": "eth0",
  "promiscuous": true,
  "snap_len": 65535,
  "bpf_filter": "",
  "pcap_output": "capture.pcap",
  "log_file": "intrusion_shield.log",
  "log_level": "info",
  "rules_file": "rules/default.rules",
  "anomaly_threshold": 3.0,
  "window_size": 100,
  "database_url": "postgres://intrusion:shield@localhost:5432/intrusion_shield?sslmode=disable",
  "slack_webhook": "",
  "email_smtp": "smtp.example.com:25",
  "email_from": "ids@example.com",
  "email_to": "secops@example.com",
  "telegram_token": "",
  "telegram_chat_id": "",
  "webhook_url": "",
  "dashboard_port": 8080
}
```

## Custom Rules

Add Snort-compatible rules to `rules/default.rules`:

```
alert tcp any any -> any 8080 (msg:"HTTP alt port access"; sid:2000001; rev:1; severity:1)
alert tcp any any -> any any (msg:"Base64 encoded payload"; content:"base64"; nocase; sid:2000002; rev:1; severity:2)
```

## Project Structure

```
IntrusionShield/
├── main.go                  # Orchestration + CLI flags
├── config/config.go         # Config struct + JSON load/save
├── capture/
│   ├── sniffer.go           # libpcap live capture + pcap write
│   └── filters.go           # BPF filter builder
├── parser/
│   ├── packet.go            # Normalized Packet type + Parse()
│   ├── ip.go                # IPv4/IPv6 layer
│   ├── tcp.go               # TCP flags + payload
│   ├── udp.go               # UDP payload
│   ├── icmp.go              # ICMPv4/ICMPv6
│   ├── dns.go               # DNS query/answer parsing
│   └── http.go              # HTTP/1.x layer-7 parsing
├── detection/
│   ├── engine.go            # Signature matching pipeline + Alert type
│   ├── rules.go             # Snort-like rules file parser
│   ├── signatures.go        # 16 built-in signatures
│   └── anomaly.go           # Statistical anomaly detector
├── storage/
│   ├── db.go                # pgxpool connection + migrations + queries
│   └── models.go            # AlertRecord, AnomalyRecord, PacketRecord
├── alert/
│   ├── notifier.go          # Multi-channel dispatcher
│   ├── slack.go             # Slack webhook
│   ├── email.go             # SMTP email
│   ├── webhook.go           # Generic HTTP webhook (JSON)
│   └── telegram.go          # Telegram Bot API
├── dashboard/
│   └── api.go               # REST API + embedded status HTML
├── rules/
│   └── default.rules        # Custom rules (empty by default)
├── Dockerfile               # Multi-stage build (Alpine)
└── docker-compose.yml       # NIDS + PostgreSQL + Grafana
```

## Tech Stack

| Layer          | Technology                         |
|----------------|------------------------------------|
| Language       | Go 1.22+                           |
| Packet Capture | gopacket + libpcap                 |
| Storage        | PostgreSQL 16 via pgx/v5           |
| HTTP API       | gorilla/mux                        |
| Alerting       | Slack / Email / Telegram / Webhook |
| Deployment     | Docker + Docker Compose            |

## Alert Severity

| Level  | Value | Examples                                    |
|--------|-------|---------------------------------------------|
| HIGH   | 3     | SQLi, XSS, reverse shell, shell injection   |
| MEDIUM | 2     | Port scans, SMB access, Telnet, RDP         |
| LOW    | 1     | FTP connections, ICMP packets               |
