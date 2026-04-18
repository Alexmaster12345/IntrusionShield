from __future__ import annotations
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional

import psycopg2
import psycopg2.extras
from psycopg2.extensions import connection as PgConnection

from detection.engine import Alert
from detection.anomaly import AnomalyAlert
from parser.packet import Packet
from storage.models import AlertRecord, AnomalyRecord, PacketRecord

logger = logging.getLogger(__name__)


class DB:
    def __init__(self, conn: PgConnection):
        self._conn = conn

    @classmethod
    def connect(cls, dsn: str) -> "DB":
        conn = psycopg2.connect(dsn)
        conn.autocommit = True
        db = cls(conn)
        db._migrate()
        logger.info("Connected to PostgreSQL")
        return db

    def close(self) -> None:
        self._conn.close()

    def _migrate(self) -> None:
        with self._conn.cursor() as cur:
            cur.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id          BIGSERIAL PRIMARY KEY,
                timestamp   TIMESTAMPTZ NOT NULL,
                rule_id     INT,
                sid         INT,
                severity    INT,
                msg         TEXT,
                protocol    TEXT,
                src_ip      TEXT,
                dst_ip      TEXT,
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
                src_ip      TEXT,
                dst_ip      TEXT,
                src_port    INT,
                dst_port    INT,
                length      INT,
                dns_query   TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_alerts_ts  ON alerts(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_packets_ts ON packets(timestamp DESC);
            """)

    def save_alert(self, a: Alert) -> None:
        with self._conn.cursor() as cur:
            cur.execute(
                """INSERT INTO alerts
                   (timestamp,rule_id,sid,severity,msg,protocol,src_ip,dst_ip,src_port,dst_port,payload_hex)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (a.timestamp, a.rule_id, a.sid, a.severity, a.msg,
                 a.protocol, a.src_ip, a.dst_ip, a.src_port, a.dst_port,
                 a.payload.hex()),
            )

    def save_anomaly(self, a: AnomalyAlert) -> None:
        with self._conn.cursor() as cur:
            cur.execute(
                """INSERT INTO anomalies
                   (timestamp,type,description,value,mean,std_dev,z_score,src_ip)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
                (a.timestamp, a.type, a.description, a.value, a.mean, a.std_dev, a.z_score, a.src_ip),
            )

    def save_packet(self, p: Packet) -> None:
        with self._conn.cursor() as cur:
            cur.execute(
                """INSERT INTO packets
                   (timestamp,protocol,src_ip,dst_ip,src_port,dst_port,length,dns_query)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
                (p.timestamp, p.protocol, p.src_ip, p.dst_ip,
                 p.src_port, p.dst_port, p.length, p.dns_query),
            )

    def recent_alerts(self, limit: int = 100) -> List[AlertRecord]:
        with self._conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT %s", (limit,)
            )
            return [
                AlertRecord(**dict(row))
                for row in cur.fetchall()
            ]

    def stats(self) -> Dict[str, int]:
        result: Dict[str, int] = {}
        now = datetime.utcnow()

        with self._conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM alerts")
            result["total_alerts"] = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM alerts WHERE timestamp > %s", (now - timedelta(hours=1),))
            result["alerts_last_hour"] = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM alerts WHERE severity = 3")
            result["high_severity"] = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM packets WHERE timestamp > %s", (now - timedelta(minutes=1),))
            result["packets_last_minute"] = cur.fetchone()[0]

        return result
