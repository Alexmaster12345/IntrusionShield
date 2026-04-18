package parser

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func parseUDP(p *Packet, raw gopacket.Packet) {
	udpLayer := raw.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}
	udp := udpLayer.(*layers.UDP)

	p.Protocol = "UDP"
	p.SrcPort = uint16(udp.SrcPort)
	p.DstPort = uint16(udp.DstPort)
	p.Payload = udp.Payload
}
