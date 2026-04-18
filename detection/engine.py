from __future__ import annotations
import ipaddress
import logging
import queue
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

from detection.rules import Rule, load_rules
from detection.signatures import default_signatures
from parser.packet import Packet, TCPFlags

logger = logging.getLogger(__name__)

SEVERITY_LOW = 1
SEVERITY_MEDIUM = 2
SEVERITY_HIGH = 3


@dataclass
class Alert:
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
    payload: bytes = field(default=b"", repr=False)


class Engine:
    def __init__(self, rules_file: str = ""):
        self.rules: List[Rule] = list(default_signatures())

        if rules_file:
            try:
                file_rules = load_rules(rules_file)
                self.rules.extend(file_rules)
                logger.info("Loaded %d rules from %s", len(file_rules), rules_file)
            except Exception as e:
                logger.warning("Could not load rules file %r: %s — using built-in only", rules_file, e)

        logger.info("Detection engine ready with %d rules", len(self.rules))
        self.alert_queue: queue.Queue[Alert] = queue.Queue(maxsize=500)

    def inspect(self, p: Packet) -> None:
        for rule in self.rules:
            if self._matches(rule, p):
                a = Alert(
                    timestamp=p.timestamp,
                    rule_id=rule.id,
                    sid=rule.sid,
                    severity=rule.severity,
                    msg=rule.msg,
                    protocol=p.protocol,
                    src_ip=p.src_ip,
                    dst_ip=p.dst_ip,
                    src_port=p.src_port,
                    dst_port=p.dst_port,
                    payload=p.payload,
                )
                try:
                    self.alert_queue.put_nowait(a)
                except queue.Full:
                    pass

    def _matches(self, r: Rule, p: Packet) -> bool:
        if r.protocol != "any" and r.protocol.upper() != p.protocol.upper():
            return False

        if r.src_ip != "any" and not _ip_matches(r.src_ip, p.src_ip):
            return False

        if r.src_port not in ("any", "") and not _port_matches(r.src_port, p.src_port):
            return False

        if r.dst_ip != "any" and not _ip_matches(r.dst_ip, p.dst_ip):
            return False

        if r.dst_port not in ("any", "") and not _port_matches(r.dst_port, p.dst_port):
            return False

        if r.flags and p.protocol.upper() == "TCP":
            if not _flags_match(r.flags, p.flags):
                return False

        if r.content:
            payload = p.payload
            content = r.content.encode()
            if r.nocase:
                payload = payload.lower()
                content = content.lower()
            if content not in payload:
                return False

        return True


def _ip_matches(spec: str, ip: str) -> bool:
    if spec == "any" or not ip:
        return True
    try:
        if "/" in spec:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(spec, strict=False)
        return ipaddress.ip_address(ip) == ipaddress.ip_address(spec)
    except ValueError:
        return False


def _port_matches(spec: str, port: int) -> bool:
    if spec in ("any", ""):
        return True
    if ":" in spec:
        lo, hi = spec.split(":", 1)
        return int(lo) <= port <= int(hi)
    if spec.startswith("!"):
        return port != int(spec[1:])
    try:
        return port == int(spec)
    except ValueError:
        return False


def _flags_match(spec: str, f: TCPFlags) -> bool:
    if spec == "0":
        return not any([f.syn, f.ack, f.rst, f.fin, f.psh, f.urg])
    mapping = {"S": f.syn, "A": f.ack, "R": f.rst, "F": f.fin, "P": f.psh, "U": f.urg}
    return all(mapping.get(c, True) for c in spec.upper())
