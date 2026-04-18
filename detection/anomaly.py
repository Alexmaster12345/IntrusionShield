from __future__ import annotations
import logging
import math
import queue
import threading
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from typing import Deque, Dict, Set, Tuple

from parser.packet import Packet

logger = logging.getLogger(__name__)


@dataclass
class AnomalyAlert:
    timestamp: datetime
    type: str
    description: str
    value: float = 0.0
    mean: float = 0.0
    std_dev: float = 0.0
    z_score: float = 0.0
    src_ip: str = ""


class Detector:
    def __init__(self, window_size: int = 100, threshold: float = 3.0):
        self.window_size = window_size
        self.threshold = threshold
        self._window: Deque[float] = deque(maxlen=window_size)
        self._lock = threading.Lock()
        self.alert_queue: queue.Queue[AnomalyAlert] = queue.Queue(maxsize=200)

        # Port scan tracking: src_ip -> {(dst_port, timestamp)}
        self._src_ports: Dict[str, Dict[int, datetime]] = defaultdict(dict)

        self._current_tick: int = 0
        self._current_count: float = 0.0

    def observe(self, p: Packet) -> None:
        with self._lock:
            tick = int(p.timestamp.timestamp())

            if tick != self._current_tick:
                if self._current_tick != 0:
                    self._window.append(self._current_count)
                    self._check_rate(p.timestamp)
                self._current_tick = tick
                self._current_count = 0.0

            self._current_count += 1

            if p.protocol.upper() == "TCP" and p.dst_port:
                src = p.src_ip
                self._src_ports[src][p.dst_port] = p.timestamp

                # Expire entries older than 10 seconds
                cutoff = p.timestamp.timestamp() - 10
                self._src_ports[src] = {
                    port: ts for port, ts in self._src_ports[src].items()
                    if ts.timestamp() >= cutoff
                }

                if len(self._src_ports[src]) >= 20:
                    self._emit(AnomalyAlert(
                        timestamp=p.timestamp,
                        type="port_scan",
                        description=f"Port scan: {src} contacted 20+ distinct ports in 10s",
                        value=float(len(self._src_ports[src])),
                        src_ip=src,
                    ))
                    self._src_ports[src] = {}

    def _check_rate(self, ts: datetime) -> None:
        if len(self._window) < 10:
            return
        data = list(self._window)
        mean, stddev = _stats(data)
        if stddev == 0:
            return
        latest = data[-1]
        z = (latest - mean) / stddev
        if abs(z) >= self.threshold:
            logger.warning("Packet rate anomaly: count=%.0f mean=%.1f stddev=%.1f z=%.2f",
                           latest, mean, stddev, z)
            self._emit(AnomalyAlert(
                timestamp=ts,
                type="packet_rate",
                description="Packet rate anomaly detected",
                value=latest,
                mean=mean,
                std_dev=stddev,
                z_score=z,
            ))

    def _emit(self, a: AnomalyAlert) -> None:
        try:
            self.alert_queue.put_nowait(a)
        except queue.Full:
            pass


def _stats(data: list) -> Tuple[float, float]:
    n = len(data)
    if n == 0:
        return 0.0, 0.0
    mean = sum(data) / n
    variance = sum((x - mean) ** 2 for x in data) / n
    return mean, math.sqrt(variance)
