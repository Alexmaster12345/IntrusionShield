#!/usr/bin/env python3
import argparse
import logging
import signal
import sys
import threading
import time

from alert.notifier import Notifier
from capture.sniffer import Sniffer, print_metadata
from config.config import load as load_config
from dashboard import api as dashboard_api
from detection.anomaly import Detector
from detection.engine import Engine
from storage.db import DB

BANNER = r"""
 ___     _                    _            ____  _     _      _     _
|_ _|_ _| |_ _ _ _  _ _____ (_)___ _ _   / ___|| |__ (_) ___| | __| |
 | || ' \  _| '_| || (_-< \ / / _ \ ' \  \___ \| '_ \| |/ _ \ |/ _' |
|___|_||_\__|_|  \_,_/__/\_V /\___/_||_| |____/|_| |_|_|\___/_|\__,_|
                                                   Network IDS v1.0.0
"""


def main() -> None:
    print(BANNER)

    parser = argparse.ArgumentParser(description="IntrusionShield — Network IDS")
    parser.add_argument("-config", default="config.json", help="path to config file")
    parser.add_argument("-iface", default="", help="network interface (overrides config)")
    parser.add_argument("-pcap", default="", help="read from pcap file instead of live capture")
    parser.add_argument("-verbose", action="store_true", help="print each packet")
    parser.add_argument("-no-db", dest="no_db", action="store_true", help="disable PostgreSQL")
    args = parser.parse_args()

    cfg = load_config(args.config)
    if args.iface:
        cfg.interface = args.iface

    _setup_logging(cfg.log_file, cfg.log_level)
    logger = logging.getLogger(__name__)
    mode = f"offline={args.pcap}" if args.pcap else f"interface={cfg.interface}"
    logger.info("IntrusionShield starting — %s", mode)

    # --- Storage ---
    db = None
    if not args.no_db:
        try:
            db = DB.connect(cfg.database_url)
        except Exception as e:
            logger.warning("DB unavailable (%s) — running without persistence", e)

    # --- Detection ---
    engine = Engine(cfg.rules_file)
    anomaly = Detector(cfg.window_size, cfg.anomaly_threshold)

    # --- Alerting ---
    notifier = Notifier(cfg)

    # --- Dashboard ---
    dash = None
    if db is not None:
        dash = dashboard_api.Server(db, cfg.dashboard_port)
        dash.start()

    # --- Capture ---
    sniffer = Sniffer(cfg)
    sniffer.start(offline=args.pcap)

    stop_event = threading.Event()

    def _shutdown(sig, frame):
        logger.info("Signal %s received — shutting down", sig)
        stop_event.set()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    logger.info("Pipeline running — press Ctrl+C to stop")
    total_packets = 0
    total_alerts = 0

    while not stop_event.is_set():
        # In offline mode, exit once the sniffer thread finishes and queue is empty
        if args.pcap and not sniffer._thread.is_alive() and sniffer.packet_queue.empty():
            break

        # Drain packet queue
        try:
            pkt = sniffer.packet_queue.get(timeout=0.1)
        except Exception:
            continue

        total_packets += 1

        if args.verbose:
            print_metadata(pkt)

        engine.inspect(pkt)
        anomaly.observe(pkt)

        if db is not None:
            try:
                db.save_packet(pkt)
            except Exception as e:
                logger.debug("save_packet error: %s", e)

        # Drain alert queues
        while not engine.alert_queue.empty():
            try:
                a = engine.alert_queue.get_nowait()
                total_alerts += 1
                logger.warning("[ALERT] [%s] %s  %s:%d → %s:%d",
                               _sev(a.severity), a.msg,
                               a.src_ip, a.src_port, a.dst_ip, a.dst_port)
                notifier.dispatch(a)
                dashboard_api.add_alert(a)
                if db is not None:
                    try:
                        db.save_alert(a)
                    except Exception as e:
                        logger.debug("save_alert error: %s", e)
            except Exception:
                break

        while not anomaly.alert_queue.empty():
            try:
                a = anomaly.alert_queue.get_nowait()
                logger.warning("[ANOMALY] %s — z=%.2f", a.description, a.z_score)
                notifier.dispatch_anomaly(a)
                if db is not None:
                    try:
                        db.save_anomaly(a)
                    except Exception as e:
                        logger.debug("save_anomaly error: %s", e)
            except Exception:
                break

    sniffer.stop()
    if dash:
        dash.stop()
    if db:
        db.close()

    logger.info("Done — %d packets processed, %d alerts generated", total_packets, total_alerts)


def _sev(s: int) -> str:
    return {1: "LOW", 2: "MEDIUM", 3: "HIGH"}.get(s, "UNKNOWN")


def _setup_logging(log_file: str, level: str) -> None:
    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        try:
            handlers.append(logging.FileHandler(log_file))
        except OSError:
            pass
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s.%(msecs)03d [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=handlers,
    )


if __name__ == "__main__":
    main()
