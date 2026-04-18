package alert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/Alexmaster12345/IntrusionShield/detection"
)

type WebhookNotifier struct {
	url string
}

type webhookPayload struct {
	Timestamp string `json:"timestamp"`
	Msg       string `json:"msg"`
	Severity  int    `json:"severity"`
	Protocol  string `json:"protocol"`
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	SrcPort   uint16 `json:"src_port"`
	DstPort   uint16 `json:"dst_port"`
}

func (w *WebhookNotifier) Send(a detection.Alert) error {
	payload := webhookPayload{
		Timestamp: a.Timestamp.Format(time.RFC3339),
		Msg:       a.Msg,
		Severity:  a.Severity,
		Protocol:  a.Protocol,
		SrcPort:   a.SrcPort,
		DstPort:   a.DstPort,
	}
	if a.SrcIP != nil {
		payload.SrcIP = a.SrcIP.String()
	}
	if a.DstIP != nil {
		payload.DstIP = a.DstIP.String()
	}

	body, _ := json.Marshal(payload)
	return w.post(body)
}

func (w *WebhookNotifier) SendRaw(msg string) error {
	body, _ := json.Marshal(map[string]string{"message": msg})
	return w.post(body)
}

func (w *WebhookNotifier) post(body []byte) error {
	resp, err := http.Post(w.url, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %d", resp.StatusCode)
	}
	return nil
}
