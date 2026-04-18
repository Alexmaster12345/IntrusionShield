import urllib.parse
import urllib.request


class TelegramNotifier:
    def __init__(self, token: str, chat_id: str):
        self.token = token
        self.chat_id = chat_id

    def send(self, msg: str) -> None:
        url = f"https://api.telegram.org/bot{self.token}/sendMessage"
        data = urllib.parse.urlencode({"chat_id": self.chat_id, "text": msg}).encode()
        req = urllib.request.Request(url, data=data)
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status != 200:
                raise RuntimeError(f"Telegram returned {resp.status}")
