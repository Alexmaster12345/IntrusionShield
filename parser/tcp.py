from scapy.layers.inet import TCP
from scapy.packet import Packet as ScapyPacket

from parser.packet import Packet, TCPFlags


def parse_tcp(p: Packet, raw: ScapyPacket) -> None:
    if not raw.haslayer(TCP):
        return

    tcp = raw[TCP]
    p.protocol = "TCP"
    p.src_port = tcp.sport
    p.dst_port = tcp.dport
    p.payload = bytes(tcp.payload)

    flags = tcp.flags
    p.flags = TCPFlags(
        syn=bool(flags & 0x02),
        ack=bool(flags & 0x10),
        rst=bool(flags & 0x04),
        fin=bool(flags & 0x01),
        psh=bool(flags & 0x08),
        urg=bool(flags & 0x20),
    )
