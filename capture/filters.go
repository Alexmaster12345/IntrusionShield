package capture

import "fmt"

// BPFFilter builds a BPF filter expression from port/protocol criteria.
type FilterConfig struct {
	Ports     []int
	Protocols []string // "tcp", "udp", "icmp", "dns"
	CaptureDNS bool
}

func BuildBPF(fc FilterConfig) string {
	if fc.Ports == nil && fc.Protocols == nil && !fc.CaptureDNS {
		return ""
	}

	var parts []string

	if fc.CaptureDNS {
		parts = append(parts, "port 53")
	}

	for _, p := range fc.Ports {
		parts = append(parts, fmt.Sprintf("port %d", p))
	}

	if len(fc.Protocols) > 0 {
		for _, proto := range fc.Protocols {
			switch proto {
			case "tcp", "udp", "icmp":
				parts = append(parts, proto)
			}
		}
	}

	if len(parts) == 0 {
		return ""
	}

	result := parts[0]
	for _, p := range parts[1:] {
		result += " or " + p
	}
	return result
}

// DefaultFilter captures TCP, UDP, ICMP and DNS.
func DefaultFilter() string {
	return BuildBPF(FilterConfig{
		Protocols:  []string{"tcp", "udp", "icmp"},
		CaptureDNS: true,
	})
}
