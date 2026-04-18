import json
import urllib.request


class SlackNotifier:
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    def send(self, msg: str) -> None:
        body = json.dumps({"text": msg}).encode()
        req = urllib.request.Request(
            self.webhook_url, data=body,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status != 200:
                raise RuntimeError(f"Slack returned {resp.status}")
