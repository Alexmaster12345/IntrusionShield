package parser

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func parseDNS(p *Packet, raw gopacket.Packet) {
	dnsLayer := raw.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return
	}
	dns := dnsLayer.(*layers.DNS)

	p.Protocol = "DNS"
	p.DNSID = dns.ID

	if len(dns.Questions) > 0 {
		q := dns.Questions[0]
		p.DNSQuery = string(q.Name)
		p.DNSQueryType = q.Type.String()
	}

	for _, ans := range dns.Answers {
		switch ans.Type {
		case layers.DNSTypeA, layers.DNSTypeAAAA:
			p.DNSAnswers = append(p.DNSAnswers, ans.IP.String())
		case layers.DNSTypeCNAME:
			p.DNSAnswers = append(p.DNSAnswers, string(ans.CNAME))
		case layers.DNSTypeMX:
			p.DNSAnswers = append(p.DNSAnswers, fmt.Sprintf("%s (pref %d)", ans.MX.Name, ans.MX.Preference))
		case layers.DNSTypeTXT:
			for _, t := range ans.TXTs {
				p.DNSAnswers = append(p.DNSAnswers, string(t))
			}
		}
	}
}
