package config

import (
	"encoding/json"
	"os"
)

type Config struct {
	// Capture
	Interface   string `json:"interface"`
	Promiscuous bool   `json:"promiscuous"`
	SnapLen     int32  `json:"snap_len"`
	BPFFilter   string `json:"bpf_filter"`

	// Output
	PcapOutput string `json:"pcap_output"`
	LogFile    string `json:"log_file"`
	LogLevel   string `json:"log_level"`

	// Detection
	RulesFile        string  `json:"rules_file"`
	AnomalyThreshold float64 `json:"anomaly_threshold"`
	WindowSize       int     `json:"window_size"`

	// Storage
	DatabaseURL string `json:"database_url"`

	// Alerting
	SlackWebhook    string `json:"slack_webhook"`
	EmailSMTP       string `json:"email_smtp"`
	EmailFrom       string `json:"email_from"`
	EmailTo         string `json:"email_to"`
	TelegramToken   string `json:"telegram_token"`
	TelegramChatID  string `json:"telegram_chat_id"`
	WebhookURL      string `json:"webhook_url"`

	// Dashboard
	DashboardPort int    `json:"dashboard_port"`
	GrafanaURL    string `json:"grafana_url"`
}

func Default() *Config {
	return &Config{
		Interface:        "eth0",
		Promiscuous:      true,
		SnapLen:          65535,
		BPFFilter:        "",
		PcapOutput:       "capture.pcap",
		LogFile:          "intrusion_shield.log",
		LogLevel:         "info",
		RulesFile:        "rules/default.rules",
		AnomalyThreshold: 3.0,
		WindowSize:       100,
		DatabaseURL:      "postgres://intrusion:shield@localhost:5432/intrusion_shield?sslmode=disable",
		DashboardPort:    8080,
	}
}

func Load(path string) (*Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, err
	}
	defer f.Close()

	if err := json.NewDecoder(f).Decode(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) Save(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(c)
}
