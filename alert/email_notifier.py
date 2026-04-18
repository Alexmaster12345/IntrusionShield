import smtplib
from email.mime.text import MIMEText


class EmailNotifier:
    def __init__(self, smtp: str, from_addr: str, to_addr: str):
        self.smtp = smtp
        self.from_addr = from_addr
        self.to_addr = to_addr

    def send(self, subject: str, body: str) -> None:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = self.from_addr
        msg["To"] = self.to_addr

        host, _, port_str = self.smtp.partition(":")
        port = int(port_str) if port_str else 25

        with smtplib.SMTP(host, port, timeout=10) as s:
            s.sendmail(self.from_addr, [self.to_addr], msg.as_string())
