package storage

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Alexmaster12345/IntrusionShield/detection"
	"github.com/Alexmaster12345/IntrusionShield/parser"
)

// DB wraps a pgxpool connection pool.
type DB struct {
	pool *pgxpool.Pool
}

// Connect opens a connection pool and runs migrations.
func Connect(ctx context.Context, dsn string) (*DB, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("open pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}
	db := &DB{pool: pool}
	if err := db.migrate(ctx); err != nil {
		return nil, err
	}
	log.Println("[storage] connected to PostgreSQL")
	return db, nil
}

// Close releases pool connections.
func (db *DB) Close() { db.pool.Close() }

// migrate creates tables if they don't exist.
func (db *DB) migrate(ctx context.Context) error {
	_, err := db.pool.Exec(ctx, `
	CREATE TABLE IF NOT EXISTS alerts (
		id          BIGSERIAL PRIMARY KEY,
		timestamp   TIMESTAMPTZ NOT NULL,
		rule_id     INT,
		sid         INT,
		severity    INT,
		msg         TEXT,
		protocol    TEXT,
		src_ip      INET,
		dst_ip      INET,
		src_port    INT,
		dst_port    INT,
		payload_hex TEXT
	);

	CREATE TABLE IF NOT EXISTS anomalies (
		id          BIGSERIAL PRIMARY KEY,
		timestamp   TIMESTAMPTZ NOT NULL,
		type        TEXT,
		description TEXT,
		value       DOUBLE PRECISION,
		mean        DOUBLE PRECISION,
		std_dev     DOUBLE PRECISION,
		z_score     DOUBLE PRECISION,
		src_ip      TEXT
	);

	CREATE TABLE IF NOT EXISTS packets (
		id          BIGSERIAL PRIMARY KEY,
		timestamp   TIMESTAMPTZ NOT NULL,
		protocol    TEXT,
		src_ip      INET,
		dst_ip      INET,
		src_port    INT,
		dst_port    INT,
		length      INT,
		dns_query   TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_alerts_timestamp  ON alerts(timestamp DESC);
	CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp DESC);
	`)
	return err
}

// SaveAlert persists a detection alert.
func (db *DB) SaveAlert(ctx context.Context, a detection.Alert) error {
	_, err := db.pool.Exec(ctx,
		`INSERT INTO alerts(timestamp,rule_id,sid,severity,msg,protocol,src_ip,dst_ip,src_port,dst_port,payload_hex)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		a.Timestamp, a.RuleID, a.Sid, a.Severity, a.Msg,
		a.Protocol, ipStr(a.SrcIP), ipStr(a.DstIP),
		a.SrcPort, a.DstPort, hex.EncodeToString(a.Payload),
	)
	return err
}

// SaveAnomaly persists an anomaly alert.
func (db *DB) SaveAnomaly(ctx context.Context, a detection.AnomalyAlert) error {
	_, err := db.pool.Exec(ctx,
		`INSERT INTO anomalies(timestamp,type,description,value,mean,std_dev,z_score,src_ip)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
		a.Timestamp, a.Type, a.Description, a.Value, a.Mean, a.StdDev, a.ZScore, a.SrcIP,
	)
	return err
}

// SavePacket persists packet metadata.
func (db *DB) SavePacket(ctx context.Context, p *parser.Packet) error {
	_, err := db.pool.Exec(ctx,
		`INSERT INTO packets(timestamp,protocol,src_ip,dst_ip,src_port,dst_port,length,dns_query)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
		p.Timestamp, p.Protocol, ipStr(p.SrcIP), ipStr(p.DstIP),
		p.SrcPort, p.DstPort, p.Length, p.DNSQuery,
	)
	return err
}

// RecentAlerts returns the latest n alerts ordered newest-first.
func (db *DB) RecentAlerts(ctx context.Context, n int) ([]AlertRecord, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT id,timestamp,rule_id,sid,severity,msg,protocol,
		        src_ip::text,dst_ip::text,src_port,dst_port,payload_hex
		 FROM alerts ORDER BY timestamp DESC LIMIT $1`, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []AlertRecord
	for rows.Next() {
		var a AlertRecord
		if err := rows.Scan(&a.ID, &a.Timestamp, &a.RuleID, &a.Sid, &a.Severity,
			&a.Msg, &a.Protocol, &a.SrcIP, &a.DstIP, &a.SrcPort, &a.DstPort, &a.PayloadHex); err != nil {
			return nil, err
		}
		alerts = append(alerts, a)
	}
	return alerts, rows.Err()
}

// Stats returns aggregate counts for the dashboard.
func (db *DB) Stats(ctx context.Context) (map[string]int64, error) {
	stats := map[string]int64{}

	var v int64

	row := db.pool.QueryRow(ctx, `SELECT COUNT(*) FROM alerts`)
	if err := row.Scan(&v); err == nil {
		stats["total_alerts"] = v
	}

	row = db.pool.QueryRow(ctx, `SELECT COUNT(*) FROM alerts WHERE timestamp > $1`, time.Now().Add(-time.Hour))
	if err := row.Scan(&v); err == nil {
		stats["alerts_last_hour"] = v
	}

	row = db.pool.QueryRow(ctx, `SELECT COUNT(*) FROM alerts WHERE severity = 3`)
	if err := row.Scan(&v); err == nil {
		stats["high_severity"] = v
	}

	row = db.pool.QueryRow(ctx, `SELECT COUNT(*) FROM packets WHERE timestamp > $1`, time.Now().Add(-time.Minute))
	if err := row.Scan(&v); err == nil {
		stats["packets_last_minute"] = v
	}

	return stats, nil
}

func ipStr(ip interface{ String() string }) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}
