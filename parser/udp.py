from scapy.layers.inet import UDP
from scapy.packet import Packet as ScapyPacket

from parser.packet import Packet


def parse_udp(p: Packet, raw: ScapyPacket) -> None:
    if not raw.haslayer(UDP):
        return

    udp = raw[UDP]
    p.protocol = "UDP"
    p.src_port = udp.sport
    p.dst_port = udp.dport
    p.payload = bytes(udp.payload)
