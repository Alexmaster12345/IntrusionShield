from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet as ScapyPacket

from parser.packet import Packet


def parse_ip(p: Packet, raw: ScapyPacket) -> None:
    if raw.haslayer(IP):
        ip = raw[IP]
        p.src_ip = ip.src
        p.dst_ip = ip.dst
        p.ttl = ip.ttl
        p.protocol = ip.proto_str if hasattr(ip, "proto_str") else str(ip.proto)
        return

    if raw.haslayer(IPv6):
        ip6 = raw[IPv6]
        p.src_ip = ip6.src
        p.dst_ip = ip6.dst
        p.ttl = ip6.hlim
        p.protocol = str(ip6.nh)
