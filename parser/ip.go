package parser

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func parseIP(p *Packet, raw gopacket.Packet) {
	if ipv4 := raw.Layer(layers.LayerTypeIPv4); ipv4 != nil {
		ip := ipv4.(*layers.IPv4)
		p.SrcIP = ip.SrcIP
		p.DstIP = ip.DstIP
		p.TTL = ip.TTL
		p.Protocol = ip.Protocol.String()
		return
	}

	if ipv6 := raw.Layer(layers.LayerTypeIPv6); ipv6 != nil {
		ip := ipv6.(*layers.IPv6)
		p.SrcIP = ip.SrcIP
		p.DstIP = ip.DstIP
		p.Protocol = ip.NextHeader.String()
	}
}
