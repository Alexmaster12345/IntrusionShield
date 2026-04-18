from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.packet import Packet as ScapyPacket

from parser.packet import Packet


def parse_dns(p: Packet, raw: ScapyPacket) -> None:
    if not raw.haslayer(DNS):
        return

    dns = raw[DNS]
    p.protocol = "DNS"
    p.dns_id = dns.id

    if dns.qd:
        try:
            p.dns_query = dns.qd.qname.decode("utf-8", errors="replace").rstrip(".")
            p.dns_query_type = _qtype_name(dns.qd.qtype)
        except Exception:
            pass

    rr = dns.an
    while rr and isinstance(rr, DNSRR):
        try:
            if rr.type == 1:  # A
                p.dns_answers.append(rr.rdata)
            elif rr.type == 28:  # AAAA
                p.dns_answers.append(rr.rdata)
            elif rr.type == 5:  # CNAME
                p.dns_answers.append(rr.rdata.decode("utf-8", errors="replace").rstrip("."))
            elif rr.type == 16:  # TXT
                p.dns_answers.append(str(rr.rdata))
        except Exception:
            pass
        rr = rr.payload if hasattr(rr, "payload") else None


def _qtype_name(qtype: int) -> str:
    names = {1: "A", 2: "NS", 5: "CNAME", 15: "MX", 16: "TXT", 28: "AAAA"}
    return names.get(qtype, str(qtype))
