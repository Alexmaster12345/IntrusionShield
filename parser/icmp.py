from scapy.layers.inet import ICMP
from scapy.packet import Packet as ScapyPacket

from parser.packet import Packet


def parse_icmp(p: Packet, raw: ScapyPacket) -> None:
    if not raw.haslayer(ICMP):
        return

    icmp = raw[ICMP]
    p.protocol = "ICMP"
    p.icmp_type = icmp.type
    p.icmp_code = icmp.code
