from detection.rules import Rule


def default_signatures():
    return [
        Rule(id=1, action="alert", protocol="TCP", src_ip="any", src_port="any",
             dst_ip="any", dst_port="any",
             msg="TCP SYN Scan detected", flags="S", severity=2, sid=1000001),

        Rule(id=2, action="alert", protocol="TCP", src_ip="any", src_port="any",
             dst_ip="any", dst_port="any",
             msg="TCP NULL Scan detected", flags="0", severity=2, sid=1000002),

        Rule(id=3, action="alert", protocol="TCP", src_ip="any", src_port="any",
             dst_ip="any", dst_port="any",
             msg="TCP XMAS Scan detected", flags="FUP", severity=2, sid=1000003),

        Rule(id=4, action="alert", protocol="TCP", src_ip="any", src_port="any",
             dst_ip="any", dst_port="22",
             msg="Possible SSH brute force", severity=3, sid=1000004),

        Rule(id=5, action="alert", protocol="TCP", src_ip="any", src_port="any",
             dst_ip="any", dst_port="21",
             msg="FTP connection attempt", severity=1, sid=1000005),

        Rule(id=6, action="alert", protocol="TCP", src_ip="any", src_port="any",
             dst_ip="any", dst_port="23",
             msg="Telnet connection (cleartext protocol)", severity=2, sid=1000006),

        Rule(id=7, action="alert", protocol="TCP", src_ip="any", src_port="any",
             dst_ip="any", dst_port="any",
             msg="SQL injection attempt (UNION SELECT)",
             content="UNION SELECT", nocase=True, severity=3, sid=1000007),

        Rule(id=8, action="alert", protocol="TCP", src_ip="any", src_port="any",
             dst_ip="any", dst_port="any",
             msg="SQL injection attempt (OR 1=1)",
             content="OR 1=1", nocase=True, severity=3, sid=1000008),

        Rule(id=9, action="alert", protocol="TCP", src_ip="any", src_port="any",
             dst_ip="any", dst_port="any",
             msg="XSS attempt (<script>)",
             content="<script>", nocase=True, severity=3, sid=1000009),

        Rule(id=10, action="alert", protocol="TCP", src_ip="any", src_port="any",
             dst_ip="any", dst_port="any",
             msg="Shell injection attempt (/bin/sh)",
             content="/bin/sh", severity=3, sid=1000010),

        Rule(id=11, action="alert", protocol="ICMP", src_ip="any", src_port="any",
             dst_ip="any", dst_port="any",
             msg="ICMP packet (potential flood)", severity=1, sid=1000011),

        Rule(id=12, action="alert", protocol="UDP", src_ip="any", src_port="any",
             dst_ip="any", dst_port="53",
             msg="DNS TXT query (possible DNS tunneling)", severity=2, sid=1000012),

        Rule(id=13, action="alert", protocol="TCP", src_ip="any", src_port="any",
             dst_ip="any", dst_port="445",
             msg="SMB access (potential EternalBlue/ransomware)", severity=2, sid=1000013),

        Rule(id=14, action="alert", protocol="TCP", src_ip="any", src_port="any",
             dst_ip="any", dst_port="3389",
             msg="RDP connection attempt", severity=2, sid=1000014),

        Rule(id=15, action="alert", protocol="TCP", src_ip="any", src_port="any",
             dst_ip="any", dst_port="any",
             msg="Possible reverse shell (bash -i)",
             content="bash -i", nocase=True, severity=3, sid=1000015),

        Rule(id=16, action="alert", protocol="TCP", src_ip="any", src_port="any",
             dst_ip="any", dst_port="any",
             msg="Possible reverse shell (nc -e)",
             content="nc -e", severity=3, sid=1000016),
    ]
