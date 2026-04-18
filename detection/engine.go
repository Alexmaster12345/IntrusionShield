package detection

import (
	"bytes"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/Alexmaster12345/IntrusionShield/parser"
)

// Severity levels
const (
	SeverityLow    = 1
	SeverityMedium = 2
	SeverityHigh   = 3
)

// Alert is generated when a rule matches a packet.
type Alert struct {
	Timestamp time.Time
	RuleID    int
	Sid       int
	Severity  int
	Msg       string
	Protocol  string
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   uint16
	DstPort   uint16
	Payload   []byte
}

// Engine is the detection pipeline that matches packets against rules.
type Engine struct {
	rules   []Rule
	AlertCh chan Alert
}

// NewEngine creates an Engine loaded with built-in + file rules.
func NewEngine(rulesFile string) (*Engine, error) {
	rules := DefaultSignatures()

	if rulesFile != "" {
		fileRules, err := LoadRules(rulesFile)
		if err != nil {
			log.Printf("[detection] could not load rules file %q: %v — using built-in only", rulesFile, err)
		} else {
			rules = append(rules, fileRules...)
			log.Printf("[detection] loaded %d rules from %s", len(fileRules), rulesFile)
		}
	}

	log.Printf("[detection] engine ready with %d rules", len(rules))

	return &Engine{
		rules:   rules,
		AlertCh: make(chan Alert, 500),
	}, nil
}

// Inspect checks a packet against all rules and emits alerts.
func (e *Engine) Inspect(p *parser.Packet) {
	for _, r := range e.rules {
		if e.matches(r, p) {
			a := Alert{
				Timestamp: p.Timestamp,
				RuleID:    r.ID,
				Sid:       r.Sid,
				Severity:  r.Severity,
				Msg:       r.Msg,
				Protocol:  p.Protocol,
				SrcIP:     p.SrcIP,
				DstIP:     p.DstIP,
				SrcPort:   p.SrcPort,
				DstPort:   p.DstPort,
				Payload:   p.Payload,
			}
			select {
			case e.AlertCh <- a:
			default:
			}
		}
	}
}

func (e *Engine) matches(r Rule, p *parser.Packet) bool {
	// Protocol match
	if r.Protocol != "any" && !strings.EqualFold(r.Protocol, p.Protocol) {
		return false
	}

	// Source IP
	if r.SrcIP != "any" && !ipMatches(r.SrcIP, p.SrcIP) {
		return false
	}

	// Source port
	if r.SrcPort != "any" && r.SrcPort != "" && !portMatches(r.SrcPort, p.SrcPort) {
		return false
	}

	// Destination IP
	if r.DstIP != "any" && !ipMatches(r.DstIP, p.DstIP) {
		return false
	}

	// Destination port
	if r.DstPort != "any" && r.DstPort != "" && !portMatches(r.DstPort, p.DstPort) {
		return false
	}

	// TCP flags
	if r.Flags != "" && p.Protocol == "TCP" {
		if !flagsMatch(r.Flags, p.Flags) {
			return false
		}
	}

	// Payload content match
	if r.Content != "" {
		payload := p.Payload
		content := []byte(r.Content)
		if r.Nocase {
			payload = bytes.ToLower(payload)
			content = bytes.ToLower(content)
		}
		if !bytes.Contains(payload, content) {
			return false
		}
	}

	return true
}

func ipMatches(cidr string, ip net.IP) bool {
	if cidr == "any" || ip == nil {
		return true
	}
	if strings.Contains(cidr, "/") {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return false
		}
		return network.Contains(ip)
	}
	return net.ParseIP(cidr).Equal(ip)
}

func portMatches(spec string, port uint16) bool {
	if spec == "any" || spec == "" {
		return true
	}
	// Range: "1024:65535"
	if strings.Contains(spec, ":") {
		parts := strings.SplitN(spec, ":", 2)
		lo, _ := strconv.ParseUint(parts[0], 10, 16)
		hi, _ := strconv.ParseUint(parts[1], 10, 16)
		return port >= uint16(lo) && port <= uint16(hi)
	}
	// Negation: "!80"
	if strings.HasPrefix(spec, "!") {
		n, _ := strconv.ParseUint(spec[1:], 10, 16)
		return port != uint16(n)
	}
	n, err := strconv.ParseUint(spec, 10, 16)
	if err != nil {
		return false
	}
	return port == uint16(n)
}

// flagsMatch checks TCP flags against a Snort-style flag string.
// "S"=SYN, "A"=ACK, "R"=RST, "F"=FIN, "P"=PSH, "U"=URG, "0"=no flags
func flagsMatch(spec string, f parser.TCPFlags) bool {
	if spec == "0" {
		return !f.SYN && !f.ACK && !f.RST && !f.FIN && !f.PSH && !f.URG
	}
	for _, c := range strings.ToUpper(spec) {
		switch c {
		case 'S':
			if !f.SYN {
				return false
			}
		case 'A':
			if !f.ACK {
				return false
			}
		case 'R':
			if !f.RST {
				return false
			}
		case 'F':
			if !f.FIN {
				return false
			}
		case 'P':
			if !f.PSH {
				return false
			}
		case 'U':
			if !f.URG {
				return false
			}
		}
	}
	return true
}
