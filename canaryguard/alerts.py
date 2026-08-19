import smtplib
import ssl
import threading
from email.mime.text import MIMEText

import requests

from .config import get_store

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

SEVERITY_EMOJI = {
    "info": "\u2139\ufe0f",      # ℹ️
    "low": "\U0001f7e1",        # 🟡
    "medium": "\U0001f7e0",     # 🟠
    "high": "\U0001f534",       # 🔴
    "critical": "\U0001f6a8",   # 🚨
}

CATEGORY_EMOJI = {
    "keylogger": "\u2328\ufe0f",         # ⌨️
    "file:created": "\U0001f4c4",        # 📄
    "file:deleted": "\U0001f5d1\ufe0f",  # 🗑️
    "file:modified": "\u270f\ufe0f",     # ✏️
    "file:moved": "\U0001f4c2",          # 📂
    "session": "\U0001f6aa",             # 🚪
    "secret:found": "\U0001f511",        # 🔑
}


class AlertManager:
    def __init__(self, config, logger=None):
        self.config = config
        self.store = get_store(config)
        self.logger = logger or print
        cfg = config.section("alerts")
        self.enabled = cfg.get("enabled", True)
        self.min_sev = cfg.get("min_severity", "medium")
        self.cooldown = cfg.get("cooldown_seconds", 60)
        self.geoip_enabled = cfg.get("geoip", True)
        self.telegram = cfg.get("telegram", {})
        self.discord = cfg.get("discord", {})
        self.slack = cfg.get("slack", {})
        self.email = cfg.get("email", {})
        self._lock = threading.Lock()
        self._last_sent = {}  # (channel, subject) -> ts

    def _within_cooldown(self, key):
        import time

        now = time.monotonic()
        last = self._last_sent.get(key, 0)
        return (now - last) < self.cooldown

    def send(self, event, category, severity, extra=""):
        if not self.enabled:
            return
        if SEVERITY_ORDER.get(severity, 0) < SEVERITY_ORDER.get(self.min_sev, 2):
            return

        src = event.get("src_host") or event.get("src_ip") or "?"
        dst_port = event.get("dst_port", "-")
        sev_emoji = SEVERITY_EMOJI.get(severity, "\U0001f534")
        cat_emoji = CATEGORY_EMOJI.get(category, "\U0001f4a1")
        lines = [
            f"{sev_emoji} {cat_emoji} *{category.upper()}* {sev_emoji}",
            f"\U0001f511 Severity: {severity}",
            f"\U0001f310 Source: `{src}`:{event.get('src_port', '-')}",
            f"\U0001f3e2 Target port: {dst_port}",
            f"\U0001f4c5 Time: {event.get('local_time', event.get('ts', ''))}",
        ]
        if extra:
            lines.append("")
            lines.append(extra)
        msg = "\n".join(lines)
        subject = f"OpenCanary [{severity}] {category} from {src}"
        self._dispatch(subject, msg, severity, event)

    def _dispatch(self, subject, msg, severity, event):
        channels = []
        if self.telegram.get("enabled") and self.telegram.get("bot_token"):
            channels.append(("telegram", self._send_telegram))
        if self.discord.get("enabled") and self.discord.get("webhook_url"):
            channels.append(("discord", self._send_discord))
        if self.slack.get("enabled") and self.slack.get("webhook_url"):
            channels.append(("slack", self._send_slack))
        if self.email.get("enabled") and self.email.get("smtp_host"):
            channels.append(("email", self._send_email))

        for name, fn in channels:
            key = (name, subject)
            if self._within_cooldown(key):
                continue
            self._last_sent[key] = __import__("time").monotonic()
            try:
                fn(subject, msg)
                self.store.insert_alert(name, subject, event.get("_id"))
                self.logger(f"[alerts] sent {name} alert: {subject}")
            except Exception as exc:
                self.logger(f"[alerts] {name} failed: {exc}")

    def _send_telegram(self, subject, msg):
        url = f"https://api.telegram.org/bot{self.telegram['bot_token']}/sendMessage"
        requests.post(
            url,
            json={"chat_id": self.telegram["chat_id"], "text": msg, "parse_mode": "Markdown"},
            timeout=10,
        )

    def _send_discord(self, subject, msg):
        requests.post(self.discord["webhook_url"], json={"content": f"**{subject}**\n```\n{msg}\n```"}, timeout=10)

    def _send_slack(self, subject, msg):
        requests.post(self.slack["webhook_url"], json={"text": f"*{subject}*\n```\n{msg}\n```"}, timeout=10)

    def _send_email(self, subject, msg):
        body = MIMEText(msg, "plain", "utf-8")
        body["Subject"] = subject
        body["From"] = self.email["from_addr"]
        body["To"] = self.email["to_addr"]
        port = self.email.get("smtp_port", 587)
        ctx = ssl.create_default_context()
        with smtplib.SMTP(self.email["smtp_host"], port, timeout=15) as server:
            if port == 465:
                server.starttls(context=ctx)
            else:
                server.starttls(context=ctx)
            if self.email.get("username"):
                server.login(self.email["username"], self.email["password"])
            server.sendmail(self.email["from_addr"], [self.email["to_addr"]], body.as_string())