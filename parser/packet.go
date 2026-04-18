package parser

import (
	"net"
	"time"

	"github.com/google/gopacket"
)

// Packet is the normalized representation of a captured network packet.
type Packet struct {
	Timestamp time.Time
	Protocol  string
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   uint16
	DstPort   uint16
	Length    int
	TTL       uint8
	Flags     TCPFlags

	// Payload
	Payload []byte

	// DNS fields (populated when Protocol == "DNS")
	DNSQuery     string
	DNSQueryType string
	DNSAnswers   []string
	DNSID        uint16

	// HTTP fields (best-effort layer-7 parse)
	HTTPMethod  string
	HTTPHost    string
	HTTPPath    string
	HTTPStatus  int

	// ICMP
	ICMPType uint8
	ICMPCode uint8

	// Raw reference (for detection engine)
	Raw gopacket.Packet
}

// TCPFlags holds individual TCP flag bits.
type TCPFlags struct {
	SYN bool
	ACK bool
	RST bool
	FIN bool
	PSH bool
	URG bool
}

// Parse converts a raw gopacket.Packet into our normalized Packet type.
// Returns nil if the packet is not worth processing (e.g. zero-length).
func Parse(raw gopacket.Packet) *Packet {
	p := &Packet{
		Timestamp: raw.Metadata().Timestamp,
		Length:    raw.Metadata().Length,
		Raw:       raw,
	}

	parseIP(p, raw)
	parseTCP(p, raw)
	parseUDP(p, raw)
	parseICMP(p, raw)
	parseDNS(p, raw)
	parseHTTP(p)

	if p.Protocol == "" {
		p.Protocol = "unknown"
	}

	if p.Length == 0 {
		return nil
	}
	return p
}
