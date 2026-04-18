import json
import urllib.request
from datetime import datetime

from detection.engine import Alert


class WebhookNotifier:
    def __init__(self, url: str):
        self.url = url

    def send(self, a: Alert) -> None:
        payload = {
            "timestamp": a.timestamp.isoformat(),
            "msg": a.msg,
            "severity": a.severity,
            "protocol": a.protocol,
            "src_ip": a.src_ip,
            "dst_ip": a.dst_ip,
            "src_port": a.src_port,
            "dst_port": a.dst_port,
        }
        self._post(payload)

    def send_raw(self, msg: str) -> None:
        self._post({"message": msg})

    def _post(self, payload: dict) -> None:
        body = json.dumps(payload).encode()
        req = urllib.request.Request(
            self.url, data=body,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status >= 300:
                raise RuntimeError(f"Webhook returned {resp.status}")
