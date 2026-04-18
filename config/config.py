import json
import os
from dataclasses import dataclass, field, asdict


@dataclass
class Config:
    # Capture
    interface: str = "eth0"
    promiscuous: bool = True
    snap_len: int = 65535
    bpf_filter: str = ""

    # Output
    pcap_output: str = "capture.pcap"
    log_file: str = "intrusion_shield.log"
    log_level: str = "INFO"

    # Detection
    rules_file: str = "rules/default.rules"
    anomaly_threshold: float = 3.0
    window_size: int = 100

    # Storage
    database_url: str = field(default_factory=lambda: os.getenv(
        "DATABASE_URL", "postgresql://intrusion:changeme@localhost:5432/intrusion_shield"
    ))

    # Alerting
    slack_webhook: str = ""
    email_smtp: str = ""
    email_from: str = ""
    email_to: str = ""
    telegram_token: str = ""
    telegram_chat_id: str = ""
    webhook_url: str = ""

    # Dashboard
    dashboard_port: int = 8080
    grafana_url: str = ""


def load(path: str = "") -> Config:
    cfg = Config()
    if not path or not os.path.exists(path):
        return cfg
    with open(path) as f:
        data = json.load(f)
    for k, v in data.items():
        if hasattr(cfg, k):
            setattr(cfg, k, v)
    return cfg


def save(cfg: Config, path: str) -> None:
    with open(path, "w") as f:
        json.dump(asdict(cfg), f, indent=2)
