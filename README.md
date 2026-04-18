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
- Python ≥ 3.10
- libpcap (`libpcap-devel` on RHEL/Fedora, `libpcap-dev` on Debian/Ubuntu)
- Root/CAP_NET_RAW for live capture

### Install

```bash
git clone https://github.com/Alexmaster12345/IntrusionShield.git
cd IntrusionShield
pip install -r requirements.txt
```

### Run (CLI sniffer mode)

```bash
sudo python main.py -iface eth0 -verbose
```

### Run with config

```bash
cp config.example.json config.json
# Edit interface, DB URL, alert webhooks
sudo python main.py -config config.json
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
├── main.py                      # Orchestration + CLI flags
├── requirements.txt             # Python dependencies
├── config/config.py             # Config dataclass + JSON load/save
├── capture/
│   ├── sniffer.py               # Scapy live capture + pcap write
│   └── filters.py               # BPF filter builder
├── parser/
│   ├── packet.py                # Normalized Packet dataclass + parse()
│   ├── ip.py                    # IPv4/IPv6 layer
│   ├── tcp.py                   # TCP flags + payload
│   ├── udp.py                   # UDP payload
│   ├── icmp.py                  # ICMPv4/ICMPv6
│   ├── dns.py                   # DNS query/answer parsing
│   └── http.py                  # HTTP/1.x layer-7 parsing
├── detection/
│   ├── engine.py                # Signature matching pipeline + Alert dataclass
│   ├── rules.py                 # Snort-like rules file parser
│   ├── signatures.py            # 16 built-in signatures
│   └── anomaly.py               # Statistical anomaly detector
├── storage/
│   ├── db.py                    # psycopg2 connection + migrations + queries
│   └── models.py                # AlertRecord, AnomalyRecord, PacketRecord
├── alert/
│   ├── notifier.py              # Multi-channel dispatcher
│   ├── slack.py                 # Slack webhook
│   ├── email_notifier.py        # SMTP email
│   ├── webhook.py               # Generic HTTP webhook (JSON)
│   └── telegram.py              # Telegram Bot API
├── dashboard/
│   └── api.py                   # Flask REST API + embedded status HTML
├── rules/
│   └── default.rules            # Custom rules (empty by default)
├── Dockerfile                   # Python 3.12-slim image
└── docker-compose.yml           # NIDS + PostgreSQL + Grafana
```

## Tech Stack

| Layer          | Technology                         |
|----------------|------------------------------------|
| Language       | Python 3.10+                       |
| Packet Capture | Scapy + libpcap                    |
| Storage        | PostgreSQL 16 via psycopg2         |
| HTTP API       | Flask                              |
| Alerting       | Slack / Email / Telegram / Webhook |
| Deployment     | Docker + Docker Compose            |

## Alert Severity

| Level  | Value | Examples                                    |
|--------|-------|---------------------------------------------|
| HIGH   | 3     | SQLi, XSS, reverse shell, shell injection   |
| MEDIUM | 2     | Port scans, SMB access, Telnet, RDP         |
| LOW    | 1     | FTP connections, ICMP packets               |
