package detection

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Rule represents a parsed Snort-like detection rule.
type Rule struct {
	ID       int
	Action   string // alert, log, pass, drop
	Protocol string // tcp, udp, icmp, any
	SrcIP    string
	SrcPort  string
	DstIP    string
	DstPort  string
	Msg      string
	Flags    string // TCP flags: S, A, R, F, P
	Content  string // payload substring match
	Nocase   bool
	Sid      int
	Rev      int
	Severity int // 1=low, 2=medium, 3=high
}

// LoadRules parses a Snort-like rules file.
// Format: action proto src_ip src_port -> dst_ip dst_port (options)
func LoadRules(path string) ([]Rule, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open rules file: %w", err)
	}
	defer f.Close()

	var rules []Rule
	scanner := bufio.NewScanner(f)
	lineNo := 0

	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		r, err := parseRule(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		r.ID = lineNo
		rules = append(rules, r)
	}
	return rules, scanner.Err()
}

func parseRule(line string) (Rule, error) {
	var r Rule

	// Split header from options: everything before first '('
	parenIdx := strings.Index(line, "(")
	if parenIdx < 0 {
		return r, fmt.Errorf("missing options section")
	}

	header := strings.Fields(strings.TrimSpace(line[:parenIdx]))
	if len(header) < 7 {
		return r, fmt.Errorf("short header: %q", line[:parenIdx])
	}

	r.Action = header[0]
	r.Protocol = header[1]
	r.SrcIP = header[2]
	r.SrcPort = header[3]
	// header[4] is the direction indicator "->" or "<>"
	r.DstIP = header[5]
	r.DstPort = header[6]

	// Parse options inside parentheses
	optStr := line[parenIdx+1:]
	if idx := strings.LastIndex(optStr, ")"); idx >= 0 {
		optStr = optStr[:idx]
	}

	for _, opt := range splitOptions(optStr) {
		kv := strings.SplitN(opt, ":", 2)
		key := strings.TrimSpace(kv[0])
		val := ""
		if len(kv) == 2 {
			val = strings.Trim(strings.TrimSpace(kv[1]), "\"")
		}

		switch key {
		case "msg":
			r.Msg = val
		case "flags":
			r.Flags = val
		case "content":
			r.Content = val
		case "nocase":
			r.Nocase = true
		case "sid":
			r.Sid, _ = strconv.Atoi(val)
		case "rev":
			r.Rev, _ = strconv.Atoi(val)
		case "severity":
			r.Severity, _ = strconv.Atoi(val)
		}
	}

	return r, nil
}

// splitOptions splits "msg:\"x\"; flags:S; ..." respecting quoted strings.
func splitOptions(s string) []string {
	var opts []string
	var cur strings.Builder
	inQuote := false

	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' {
			inQuote = !inQuote
			cur.WriteByte(c)
		} else if c == ';' && !inQuote {
			opt := strings.TrimSpace(cur.String())
			if opt != "" {
				opts = append(opts, opt)
			}
			cur.Reset()
		} else {
			cur.WriteByte(c)
		}
	}
	if opt := strings.TrimSpace(cur.String()); opt != "" {
		opts = append(opts, opt)
	}
	return opts
}
