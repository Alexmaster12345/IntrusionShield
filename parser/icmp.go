package parser

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func parseICMP(p *Packet, raw gopacket.Packet) {
	if icmp4 := raw.Layer(layers.LayerTypeICMPv4); icmp4 != nil {
		ic := icmp4.(*layers.ICMPv4)
		p.Protocol = "ICMP"
		p.ICMPType = uint8(ic.TypeCode.Type())
		p.ICMPCode = uint8(ic.TypeCode.Code())
		return
	}

	if icmp6 := raw.Layer(layers.LayerTypeICMPv6); icmp6 != nil {
		ic := icmp6.(*layers.ICMPv6)
		p.Protocol = "ICMPv6"
		p.ICMPType = uint8(ic.TypeCode.Type())
		p.ICMPCode = uint8(ic.TypeCode.Code())
	}
}
