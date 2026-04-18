package alert

import (
	"fmt"
	"log"
	"time"

	"github.com/Alexmaster12345/IntrusionShield/config"
	"github.com/Alexmaster12345/IntrusionShield/detection"
)

// Notifier dispatches alerts through configured channels.
type Notifier struct {
	cfg      *config.Config
	slack    *SlackNotifier
	email    *EmailNotifier
	webhook  *WebhookNotifier
	telegram *TelegramNotifier
}

// NewNotifier creates a Notifier wired to all enabled channels.
func NewNotifier(cfg *config.Config) *Notifier {
	n := &Notifier{cfg: cfg}

	if cfg.SlackWebhook != "" {
		n.slack = &SlackNotifier{webhookURL: cfg.SlackWebhook}
		log.Println("[alert] Slack notifications enabled")
	}
	if cfg.EmailSMTP != "" && cfg.EmailFrom != "" && cfg.EmailTo != "" {
		n.email = &EmailNotifier{smtp: cfg.EmailSMTP, from: cfg.EmailFrom, to: cfg.EmailTo}
		log.Println("[alert] Email notifications enabled")
	}
	if cfg.WebhookURL != "" {
		n.webhook = &WebhookNotifier{url: cfg.WebhookURL}
		log.Println("[alert] Webhook notifications enabled")
	}
	if cfg.TelegramToken != "" && cfg.TelegramChatID != "" {
		n.telegram = &TelegramNotifier{token: cfg.TelegramToken, chatID: cfg.TelegramChatID}
		log.Println("[alert] Telegram notifications enabled")
	}

	return n
}

// Dispatch sends a detection alert through all enabled channels.
func (n *Notifier) Dispatch(a detection.Alert) {
	msg := formatAlert(a)

	if n.slack != nil {
		if err := n.slack.Send(msg); err != nil {
			log.Printf("[alert] slack error: %v", err)
		}
	}
	if n.email != nil {
		if err := n.email.Send("[IntrusionShield] "+a.Msg, msg); err != nil {
			log.Printf("[alert] email error: %v", err)
		}
	}
	if n.webhook != nil {
		if err := n.webhook.Send(a); err != nil {
			log.Printf("[alert] webhook error: %v", err)
		}
	}
	if n.telegram != nil {
		if err := n.telegram.Send(msg); err != nil {
			log.Printf("[alert] telegram error: %v", err)
		}
	}
}

// DispatchAnomaly sends an anomaly alert through all enabled channels.
func (n *Notifier) DispatchAnomaly(a detection.AnomalyAlert) {
	msg := formatAnomaly(a)

	if n.slack != nil {
		_ = n.slack.Send(msg)
	}
	if n.telegram != nil {
		_ = n.telegram.Send(msg)
	}
	if n.webhook != nil {
		_ = n.webhook.SendRaw(msg)
	}
}

func formatAlert(a detection.Alert) string {
	sev := map[int]string{1: "LOW", 2: "MEDIUM", 3: "HIGH"}[a.Severity]
	return fmt.Sprintf(
		"[IntrusionShield] ALERT [%s]\nTime: %s\nRule: %s (SID %d)\nProto: %s  %s:%d → %s:%d",
		sev, a.Timestamp.Format(time.RFC3339),
		a.Msg, a.Sid,
		a.Protocol,
		ipOrEmpty(a.SrcIP), a.SrcPort,
		ipOrEmpty(a.DstIP), a.DstPort,
	)
}

func formatAnomaly(a detection.AnomalyAlert) string {
	return fmt.Sprintf(
		"[IntrusionShield] ANOMALY\nTime: %s\nType: %s\n%s\nValue: %.1f  Mean: %.1f  StdDev: %.1f  Z: %.2f",
		a.Timestamp.Format(time.RFC3339),
		a.Type, a.Description,
		a.Value, a.Mean, a.StdDev, a.ZScore,
	)
}

func ipOrEmpty(ip interface{ String() string }) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}
