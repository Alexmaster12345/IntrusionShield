# IntrusionShield

A Network Intrusion Detection System (NIDS) built in Python — live packet capture, signature detection, anomaly analysis, multi-channel alerting, and a real-time web dashboard.

```
 ___     _                    _            ____  _     _      _     _
|_ _|_ _| |_ _ _ _  _ _____ (_)___ _ _   / ___|| |__ (_) ___| | __| |
 | || ' \  _| '_| || (_-< \ / / _ \ ' \  \___ \| '_ \| |/ _ \ |/ _' |
|___|_||_\__|_|  \_,_/__/\_V /\___/_||_| |____/|_| |_|_|\___/_|\__,_|
                                                   Network IDS v1.0.0
```

## Features

### Packet Capture
- Live capture from any network interface via Scapy + libpcap
- Offline analysis from `.pcap` files (`-pcap` flag)
- Promiscuous mode, BPF filter support
- Rate-limited verbose output (`-rate` flag, default 10 pkt/s)

### Protocol Parsing
- Full layer decomposition: Ethernet → IPv4/IPv6 → TCP/UDP/ICMP
- HTTP/1.x best-effort parsing (method, path, host, status)
- DNS query/response parsing (A, AAAA, CNAME, MX, TXT)
- ICMPv4/v6 type and code extraction

### Signature Detection
16 built-in signatures + Snort-compatible custom rules file:

| Category | Signatures |
|---|---|
| Port scans | SYN scan, NULL scan, XMAS scan |
| Brute force | SSH (SYN-only), FTP, RDP |
| Dangerous protocols | Telnet, SMB / EternalBlue |
| Injection | SQL (UNION SELECT, OR 1=1), XSS (`<script>`), shell (`/bin/sh`) |
| Reverse shells | `bash -i`, `nc -e` |
| Tunneling | DNS TXT query patterns |

Rule options: protocol, CIDR src/dst, port ranges, TCP flags, payload `content` match with optional `nocase`.

### Anomaly Detection
- Z-score packet rate detector (rolling window, configurable threshold)
- Port scan heuristic: alert when a source contacts 20+ distinct ports in 10 seconds
- Default threshold: Z ≥ 3.0

### Web Dashboard
Real-time dashboard at `http://localhost:8080`:

- **Overview** — stat cards (Packets, Alerts, High Severity, Last Hour) — clickable to filter the alert table
- **Packets/s chart** — live 60-second line chart
- **Alert timeline** — stacked bar chart by severity (last 2 minutes)
- **Protocol distribution** — doughnut chart
- **Alerts page** — full filterable/searchable alert feed
- **Top Sources** — ranked source IPs with horizontal bar chart

No database required — all stats tracked in-memory. PostgreSQL adds persistence.

### Alerting
| Channel  | Config key |
|---|---|
| Slack | `slack_webhook` |
| Email | `email_smtp`, `email_from`, `email_to` |
| Webhook | `webhook_url` |
| Telegram | `telegram_token`, `telegram_chat_id` |

### Storage
- PostgreSQL 16 (optional) — auto-migrates schema on startup
- Tables: `alerts`, `anomalies`, `packets`
- Indexed by timestamp for fast dashboard queries

---

## Quick Start

### Prerequisites
- Python ≥ 3.9
- `libpcap` (`libpcap-devel` on RHEL/Fedora, `libpcap-dev` on Debian/Ubuntu)
- Root or `CAP_NET_RAW` for live capture

### Install

```bash
git clone https://github.com/Alexmaster12345/IntrusionShield.git
cd IntrusionShield
pip install -r requirements.txt
```

### Live capture

```bash
sudo python3 main.py -iface eth0
```

### Offline (pcap file)

```bash
# Generate a demo pcap with attack traffic
python3 tools/gen_demo_pcap.py

# Analyse it (no root needed)
python3 main.py -pcap demo.pcap -verbose
```

### With all flags

```bash
sudo python3 main.py \
  -config config.json \
  -iface eth0 \
  -verbose \
  -rate 5 \
  -no-db
```

| Flag | Default | Description |
|---|---|---|
| `-config` | `config.json` | Path to config file |
| `-iface` | from config | Network interface |
| `-pcap` | — | Read from pcap instead of live capture |
| `-verbose` | off | Print each packet |
| `-rate` | `10` | Max packets printed per second in verbose mode |
| `-no-db` | off | Disable PostgreSQL (dashboard still runs) |

### Docker Compose (full stack)

```bash
cp .env.example .env
# Edit .env — set POSTGRES_PASSWORD and GRAFANA_PASSWORD
docker compose up -d
```

Starts:
- IntrusionShield NIDS
- PostgreSQL 16 (alerts + packet storage)
- Grafana (`http://localhost:3000`, pre-wired to PostgreSQL)

---

## Configuration

`config.json` (all fields optional — sensible defaults apply):

```json
{
  "interface": "eth0",
  "promiscuous": true,
  "snap_len": 65535,
  "bpf_filter": "",
  "pcap_output": "capture.pcap",
  "log_file": "intrusion_shield.log",
  "log_level": "INFO",
  "rules_file": "rules/default.rules",
  "anomaly_threshold": 3.0,
  "window_size": 100,
  "database_url": "postgresql://intrusion:YOUR_PASSWORD@localhost:5432/intrusion_shield",
  "slack_webhook": "",
  "email_smtp": "smtp.example.com:587",
  "email_from": "ids@your-domain.com",
  "email_to": "secops@your-domain.com",
  "telegram_token": "",
  "telegram_chat_id": "",
  "webhook_url": "",
  "dashboard_port": 8080
}
```

`DATABASE_URL` environment variable overrides `database_url` in config.

---

## Custom Rules

Add Snort-compatible rules to `rules/default.rules`:

```
alert tcp any any -> any 8080 (msg:"HTTP alt port"; sid:3000001; rev:1; severity:1)
alert tcp any any -> any any (msg:"Suspicious user-agent"; content:"zgrab"; nocase; sid:3000002; rev:1; severity:2)
```

**Rule format:** `action proto src_ip src_port -> dst_ip dst_port (options)`

Supported options: `msg`, `content`, `nocase`, `flags`, `sid`, `rev`, `severity`

---

## Alert Severity

| Level | Value | Examples |
|---|---|---|
| HIGH | 3 | SQLi, XSS, reverse shell, shell injection, SSH brute force |
| MEDIUM | 2 | Port scans, SMB, Telnet, RDP, DNS tunneling |
| LOW | 1 | FTP connections, ICMP |

---

## Project Structure

```
IntrusionShield/
├── main.py                  # CLI entry point + pipeline orchestration
├── requirements.txt
├── .env.example             # Environment variable template
├── config/
│   └── config.py            # Config dataclass + JSON loader
├── capture/
│   ├── sniffer.py           # Scapy live/offline capture
│   └── filters.py           # BPF filter builder
├── parser/
│   ├── packet.py            # Normalized Packet dataclass
│   ├── ip.py / tcp.py / udp.py / icmp.py
│   ├── dns.py               # DNS parsing
│   └── http.py              # HTTP/1.x layer-7 parsing
├── detection/
│   ├── engine.py            # Signature matching + Alert dataclass
│   ├── rules.py             # Snort-compatible rules parser
│   ├── signatures.py        # 16 built-in signatures
│   └── anomaly.py           # Z-score + port scan detector
├── storage/
│   └── db.py                # psycopg2 + auto-migration + queries
├── alert/
│   ├── notifier.py          # Multi-channel dispatcher
│   ├── slack.py
│   ├── email_notifier.py
│   ├── webhook.py
│   └── telegram.py
├── dashboard/
│   └── api.py               # Flask REST API + embedded web UI
├── rules/
│   └── default.rules        # Custom rules (Snort format)
├── tools/
│   └── gen_demo_pcap.py     # Generates demo.pcap with attack traffic
├── Dockerfile
└── docker-compose.yml
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.9+ |
| Packet capture | Scapy + libpcap |
| Storage | PostgreSQL 16 via psycopg2 |
| Web API | Flask |
| Charts | Chart.js 4.4 |
| Alerting | Slack / Email / Telegram / Webhook |
| Deployment | Docker + Docker Compose |
