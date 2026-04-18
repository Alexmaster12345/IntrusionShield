import logging
import queue
import threading
import time
from typing import Optional

from scapy.all import sniff, wrpcap, PcapWriter
from scapy.packet import Packet as ScapyPacket

from capture.filters import default_filter
from config.config import Config
from parser.packet import Packet, parse

logger = logging.getLogger(__name__)


def print_metadata(p: Packet) -> None:
    ts = p.timestamp.strftime("%H:%M:%S.%f")
    line = f"[{ts}] {p.protocol}  {p.src_ip} -> {p.dst_ip}  len={p.length}"
    if p.src_port or p.dst_port:
        line += f"  {p.src_port} -> {p.dst_port}"
    if p.dns_query:
        line += f"  DNS={p.dns_query}"
    if p.http_method:
        line += f"  HTTP {p.http_method} {p.http_host}"
    print(line)


class Sniffer:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.packet_queue: queue.Queue[Packet] = queue.Queue(maxsize=1000)
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._pcap_writer: Optional[PcapWriter] = None
        self._count = 0
        self._start_time: Optional[float] = None

    def start(self) -> None:
        bpf = self.cfg.bpf_filter or default_filter()

        if self.cfg.pcap_output:
            self._pcap_writer = PcapWriter(self.cfg.pcap_output, append=False, sync=True)
            logger.info("Saving packets to %s", self.cfg.pcap_output)

        logger.info("Listening on %s (promiscuous=%s)  filter=%r",
                    self.cfg.interface, self.cfg.promiscuous, bpf)

        self._start_time = time.time()
        self._thread = threading.Thread(target=self._capture_loop, args=(bpf,), daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=3)
        if self._pcap_writer:
            self._pcap_writer.close()
        elapsed = time.time() - (self._start_time or time.time())
        logger.info("Capture stopped — %d packets in %.1fs", self._count, elapsed)

    def _capture_loop(self, bpf: str) -> None:
        sniff(
            iface=self.cfg.interface,
            filter=bpf,
            prn=self._handle_packet,
            store=False,
            stop_filter=lambda _: self._stop_event.is_set(),
        )

    def _handle_packet(self, raw: ScapyPacket) -> None:
        if self._pcap_writer:
            try:
                self._pcap_writer.write(raw)
            except Exception as e:
                logger.warning("pcap write error: %s", e)

        parsed = parse(raw)
        if parsed is None:
            return

        self._count += 1
        try:
            self.packet_queue.put_nowait(parsed)
        except queue.Full:
            pass  # drop to preserve capture continuity
