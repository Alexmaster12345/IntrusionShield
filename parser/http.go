package parser

import (
	"bufio"
	"bytes"
	"net/http"
	"strconv"
	"strings"
)

// parseHTTP does a best-effort layer-7 parse of TCP payload for HTTP/1.x.
func parseHTTP(p *Packet) {
	if p.Protocol != "TCP" || len(p.Payload) < 4 {
		return
	}

	// Try parsing as HTTP request
	if isHTTPRequest(p.Payload) {
		req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(p.Payload)))
		if err == nil {
			p.HTTPMethod = req.Method
			p.HTTPHost = req.Host
			p.HTTPPath = req.URL.RequestURI()
			return
		}
	}

	// Try parsing as HTTP response
	if isHTTPResponse(p.Payload) {
		resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(p.Payload)), nil)
		if err == nil {
			p.HTTPStatus = resp.StatusCode
		}
	}
}

func isHTTPRequest(b []byte) bool {
	methods := []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT "}
	for _, m := range methods {
		if bytes.HasPrefix(b, []byte(m)) {
			return true
		}
	}
	return false
}

func isHTTPResponse(b []byte) bool {
	if !bytes.HasPrefix(b, []byte("HTTP/")) {
		return false
	}
	line := strings.SplitN(string(b[:min(len(b), 20)]), " ", 3)
	if len(line) < 2 {
		return false
	}
	_, err := strconv.Atoi(line[1])
	return err == nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
