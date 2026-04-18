from __future__ import annotations
import logging
from datetime import datetime
from typing import Optional

from alert.email_notifier import EmailNotifier
from alert.slack import SlackNotifier
from alert.telegram import TelegramNotifier
from alert.webhook import WebhookNotifier
from config.config import Config
from detection.anomaly import AnomalyAlert
from detection.engine import Alert

logger = logging.getLogger(__name__)

_SEV = {1: "LOW", 2: "MEDIUM", 3: "HIGH"}


class Notifier:
    def __init__(self, cfg: Config):
        self._slack: Optional[SlackNotifier] = None
        self._email: Optional[EmailNotifier] = None
        self._webhook: Optional[WebhookNotifier] = None
        self._telegram: Optional[TelegramNotifier] = None

        if cfg.slack_webhook:
            self._slack = SlackNotifier(cfg.slack_webhook)
            logger.info("Slack notifications enabled")

        if cfg.email_smtp and cfg.email_from and cfg.email_to:
            self._email = EmailNotifier(cfg.email_smtp, cfg.email_from, cfg.email_to)
            logger.info("Email notifications enabled")

        if cfg.webhook_url:
            self._webhook = WebhookNotifier(cfg.webhook_url)
            logger.info("Webhook notifications enabled")

        if cfg.telegram_token and cfg.telegram_chat_id:
            self._telegram = TelegramNotifier(cfg.telegram_token, cfg.telegram_chat_id)
            logger.info("Telegram notifications enabled")

    def dispatch(self, a: Alert) -> None:
        msg = _format_alert(a)
        self._send_all(msg, a)

    def dispatch_anomaly(self, a: AnomalyAlert) -> None:
        msg = _format_anomaly(a)
        for sender, name in [(self._slack, "slack"), (self._telegram, "telegram")]:
            if sender:
                try:
                    sender.send(msg)
                except Exception as e:
                    logger.warning("%s error: %s", name, e)
        if self._webhook:
            try:
                self._webhook.send_raw(msg)
            except Exception as e:
                logger.warning("webhook error: %s", e)

    def _send_all(self, msg: str, a: Alert) -> None:
        if self._slack:
            try:
                self._slack.send(msg)
            except Exception as e:
                logger.warning("slack error: %s", e)

        if self._email:
            try:
                self._email.send(f"[IntrusionShield] {a.msg}", msg)
            except Exception as e:
                logger.warning("email error: %s", e)

        if self._webhook:
            try:
                self._webhook.send(a)
            except Exception as e:
                logger.warning("webhook error: %s", e)

        if self._telegram:
            try:
                self._telegram.send(msg)
            except Exception as e:
                logger.warning("telegram error: %s", e)


def _format_alert(a: Alert) -> str:
    return (
        f"[IntrusionShield] ALERT [{_SEV.get(a.severity, 'UNKNOWN')}]\n"
        f"Time: {a.timestamp.isoformat()}\n"
        f"Rule: {a.msg} (SID {a.sid})\n"
        f"Proto: {a.protocol}  {a.src_ip}:{a.src_port} → {a.dst_ip}:{a.dst_port}"
    )


def _format_anomaly(a: AnomalyAlert) -> str:
    return (
        f"[IntrusionShield] ANOMALY\n"
        f"Time: {a.timestamp.isoformat()}\n"
        f"Type: {a.type}\n"
        f"{a.description}\n"
        f"Value: {a.value:.1f}  Mean: {a.mean:.1f}  StdDev: {a.std_dev:.1f}  Z: {a.z_score:.2f}"
    )
