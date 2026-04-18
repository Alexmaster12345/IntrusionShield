package storage

import "time"

// AlertRecord maps to the alerts table.
type AlertRecord struct {
	ID          int64     `db:"id"`
	Timestamp   time.Time `db:"timestamp"`
	RuleID      int       `db:"rule_id"`
	Sid         int       `db:"sid"`
	Severity    int       `db:"severity"`
	Msg         string    `db:"msg"`
	Protocol    string    `db:"protocol"`
	SrcIP       string    `db:"src_ip"`
	DstIP       string    `db:"dst_ip"`
	SrcPort     int       `db:"src_port"`
	DstPort     int       `db:"dst_port"`
	PayloadHex  string    `db:"payload_hex"`
}

// AnomalyRecord maps to the anomalies table.
type AnomalyRecord struct {
	ID          int64     `db:"id"`
	Timestamp   time.Time `db:"timestamp"`
	Type        string    `db:"type"`
	Description string    `db:"description"`
	Value       float64   `db:"value"`
	Mean        float64   `db:"mean"`
	StdDev      float64   `db:"std_dev"`
	ZScore      float64   `db:"z_score"`
	SrcIP       string    `db:"src_ip"`
}

// PacketRecord maps to the packets table (summary, not full payload).
type PacketRecord struct {
	ID        int64     `db:"id"`
	Timestamp time.Time `db:"timestamp"`
	Protocol  string    `db:"protocol"`
	SrcIP     string    `db:"src_ip"`
	DstIP     string    `db:"dst_ip"`
	SrcPort   int       `db:"src_port"`
	DstPort   int       `db:"dst_port"`
	Length    int       `db:"length"`
	DNSQuery  string    `db:"dns_query"`
}
