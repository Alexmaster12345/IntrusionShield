from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

from scapy.packet import Packet as ScapyPacket


@dataclass
class TCPFlags:
    syn: bool = False
    ack: bool = False
    rst: bool = False
    fin: bool = False
    psh: bool = False
    urg: bool = False


@dataclass
class Packet:
    timestamp: datetime
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    length: int
    ttl: int
    flags: TCPFlags

    payload: bytes

    # DNS
    dns_query: str = ""
    dns_query_type: str = ""
    dns_answers: List[str] = field(default_factory=list)
    dns_id: int = 0

    # HTTP
    http_method: str = ""
    http_host: str = ""
    http_path: str = ""
    http_status: int = 0

    # ICMP
    icmp_type: int = 0
    icmp_code: int = 0

    raw: Optional[ScapyPacket] = field(default=None, repr=False)


def parse(raw: ScapyPacket) -> Optional[Packet]:
    from parser.ip import parse_ip
    from parser.tcp import parse_tcp
    from parser.udp import parse_udp
    from parser.icmp import parse_icmp
    from parser.dns import parse_dns
    from parser.http import parse_http

    ts = datetime.fromtimestamp(float(raw.time))
    length = len(raw)

    p = Packet(
        timestamp=ts,
        protocol="unknown",
        src_ip="",
        dst_ip="",
        src_port=0,
        dst_port=0,
        length=length,
        ttl=0,
        flags=TCPFlags(),
        payload=b"",
        raw=raw,
    )

    parse_ip(p, raw)
    parse_tcp(p, raw)
    parse_udp(p, raw)
    parse_icmp(p, raw)
    parse_dns(p, raw)
    parse_http(p)

    if length == 0:
        return None
    return p
