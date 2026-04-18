package detection

// DefaultSignatures returns built-in rules that catch common attacks.
// These supplement any loaded rules file.
func DefaultSignatures() []Rule {
	return []Rule{
		// Port scans
		{ID: 1, Action: "alert", Protocol: "tcp", SrcIP: "any", SrcPort: "any",
			DstIP: "any", DstPort: "any",
			Msg: "TCP SYN Scan detected", Flags: "S", Severity: 2, Sid: 1000001},

		// NULL scan (no flags)
		{ID: 2, Action: "alert", Protocol: "tcp", SrcIP: "any", SrcPort: "any",
			DstIP: "any", DstPort: "any",
			Msg: "TCP NULL Scan detected", Flags: "0", Severity: 2, Sid: 1000002},

		// XMAS scan (FIN+URG+PSH)
		{ID: 3, Action: "alert", Protocol: "tcp", SrcIP: "any", SrcPort: "any",
			DstIP: "any", DstPort: "any",
			Msg: "TCP XMAS Scan detected", Flags: "FUP", Severity: 2, Sid: 1000003},

		// SSH brute force attempt
		{ID: 4, Action: "alert", Protocol: "tcp", SrcIP: "any", SrcPort: "any",
			DstIP: "any", DstPort: "22",
			Msg: "Possible SSH brute force", Severity: 3, Sid: 1000004},

		// FTP brute force
		{ID: 5, Action: "alert", Protocol: "tcp", SrcIP: "any", SrcPort: "any",
			DstIP: "any", DstPort: "21",
			Msg: "FTP connection attempt", Severity: 1, Sid: 1000005},

		// Telnet (plaintext)
		{ID: 6, Action: "alert", Protocol: "tcp", SrcIP: "any", SrcPort: "any",
			DstIP: "any", DstPort: "23",
			Msg: "Telnet connection (cleartext protocol)", Severity: 2, Sid: 1000006},

		// SQL injection patterns
		{ID: 7, Action: "alert", Protocol: "tcp", SrcIP: "any", SrcPort: "any",
			DstIP: "any", DstPort: "any",
			Msg: "SQL injection attempt (UNION SELECT)", Content: "UNION SELECT", Nocase: true, Severity: 3, Sid: 1000007},

		{ID: 8, Action: "alert", Protocol: "tcp", SrcIP: "any", SrcPort: "any",
			DstIP: "any", DstPort: "any",
			Msg: "SQL injection attempt (OR 1=1)", Content: "OR 1=1", Nocase: true, Severity: 3, Sid: 1000008},

		// XSS
		{ID: 9, Action: "alert", Protocol: "tcp", SrcIP: "any", SrcPort: "any",
			DstIP: "any", DstPort: "any",
			Msg: "XSS attempt (<script>)", Content: "<script>", Nocase: true, Severity: 3, Sid: 1000009},

		// Shell command injection
		{ID: 10, Action: "alert", Protocol: "tcp", SrcIP: "any", SrcPort: "any",
			DstIP: "any", DstPort: "any",
			Msg: "Shell injection attempt (/bin/sh)", Content: "/bin/sh", Severity: 3, Sid: 1000010},

		// ICMP flood indicator
		{ID: 11, Action: "alert", Protocol: "icmp", SrcIP: "any", SrcPort: "any",
			DstIP: "any", DstPort: "any",
			Msg: "ICMP packet (potential flood)", Severity: 1, Sid: 1000011},

		// DNS suspicious TXT query
		{ID: 12, Action: "alert", Protocol: "udp", SrcIP: "any", SrcPort: "any",
			DstIP: "any", DstPort: "53",
			Msg: "DNS TXT query (possible DNS tunneling)", Severity: 2, Sid: 1000012},

		// SMB / EternalBlue port
		{ID: 13, Action: "alert", Protocol: "tcp", SrcIP: "any", SrcPort: "any",
			DstIP: "any", DstPort: "445",
			Msg: "SMB access (potential EternalBlue/ransomware)", Severity: 2, Sid: 1000013},

		// RDP brute force
		{ID: 14, Action: "alert", Protocol: "tcp", SrcIP: "any", SrcPort: "any",
			DstIP: "any", DstPort: "3389",
			Msg: "RDP connection attempt", Severity: 2, Sid: 1000014},

		// Reverse shell signatures
		{ID: 15, Action: "alert", Protocol: "tcp", SrcIP: "any", SrcPort: "any",
			DstIP: "any", DstPort: "any",
			Msg: "Possible reverse shell (bash -i)", Content: "bash -i", Nocase: true, Severity: 3, Sid: 1000015},

		{ID: 16, Action: "alert", Protocol: "tcp", SrcIP: "any", SrcPort: "any",
			DstIP: "any", DstPort: "any",
			Msg: "Possible reverse shell (nc -e)", Content: "nc -e", Severity: 3, Sid: 1000016},
	}
}
