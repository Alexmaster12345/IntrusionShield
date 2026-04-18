package parser

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func parseTCP(p *Packet, raw gopacket.Packet) {
	tcpLayer := raw.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}
	tcp := tcpLayer.(*layers.TCP)

	p.Protocol = "TCP"
	p.SrcPort = uint16(tcp.SrcPort)
	p.DstPort = uint16(tcp.DstPort)
	p.Payload = tcp.Payload
	p.Flags = TCPFlags{
		SYN: tcp.SYN,
		ACK: tcp.ACK,
		RST: tcp.RST,
		FIN: tcp.FIN,
		PSH: tcp.PSH,
		URG: tcp.URG,
	}
}
