from dataclasses import dataclass
from datetime import datetime


@dataclass
class AlertRecord:
    id: int
    timestamp: datetime
    rule_id: int
    sid: int
    severity: int
    msg: str
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    payload_hex: str


@dataclass
class AnomalyRecord:
    id: int
    timestamp: datetime
    type: str
    description: str
    value: float
    mean: float
    std_dev: float
    z_score: float
    src_ip: str


@dataclass
class PacketRecord:
    id: int
    timestamp: datetime
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    length: int
    dns_query: str
