import html
import platform
import smtplib
import ssl
import threading
import time
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
    "proc:start": "\U0001f680",          # 🚀
    "proc:exit": "\U0001f6aa",           # 🚪
    "usb:connect": "\U0001f50c",         # 🔌
    "usb:file": "\U0001f4c4",            # 📄
    "usb:open": "\U0001f4c2",            # 📂
    "usb:exec": "\u26a1",                # ⚡
    "clip:found": "\U0001f511",          # 🔑
    "clip:change": "\U0001f4cb",         # 📋
    "net:new": "\U0001f310",             # 🌐
    "auth:fail": "\U0001f512",           # 🔒
    "system:start": "\u2705",            # ✅
    "lan:new": "\U0001f4f6",             # 📶
    "dl:file": "\u2b07\ufe0f",           # ⬇️
    "cam:on": "\U0001f4f8",              # 📸
    "mic:on": "\U0001f3a4",              # 🎤
    "panic:lock": "\U0001f510",          # 🔐
    "idle:lock": "\U0001f4a4",           # 💤
    "ransomware:detected": "\U0001f525", # 🔥
    "staging:archive": "\U0001f5dc\ufe0f", # 🗜️
    "persist:new": "\u26f3",             # ⛳
    "ip:blocked": "\U0001f6ab",          # 🚫
    "theft:alarm": "\U0001f6a8",          # 🚨
    "browser:creds": "\U0001f575\ufe0f",  # 🕵️
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
        self.retries = int(cfg.get("retries", 3))
        self.geoip_enabled = cfg.get("geoip", True)
        self.muted = {c.lower() for c in (cfg.get("mute_categories", None) or [])}
        self.host = platform.node() or "PC"
        # night escalation + quiet hours
        self.night_escalate = cfg.get("night_escalation", True)
        self.night_start = cfg.get("night_start", "23:00")
        self.night_end = cfg.get("night_end", "07:00")
        self.night_floor = cfg.get("night_floor", "high")  # at night only >= floor interrupts; rest -> morning digest
        # smart batching (anti-spam): duplicates during cooldown get counted
        self.batch_limit = int(cfg.get("batch_limit", 3))
        self.batch_window = int(cfg.get("batch_window_seconds", 300))
        # screenshot attachments for critical categories
        self.shot_categories = {c.lower() for c in (cfg.get("screenshot_categories", None) or ["usb:connect", "auth:fail", "usb:exec"])}
        self.digest_time = cfg.get("digest_time", "08:00")
        # D7: attach inline [Ack] [Mute] [Block] keyboard to high/critical Telegram alerts
        self.inline_buttons = bool(cfg.get("inline_buttons", False))
        self.telegram = cfg.get("telegram", {})
        self.discord = cfg.get("discord", {})
        self.slack = cfg.get("slack", {})
        self.email = cfg.get("email", {})
        self._lock = threading.Lock()
        # One pooled HTTP session: reusing TLS connections avoids a full
        # handshake for every alert (Telegram/Discord/Slack).
        self._http = requests.Session()
        self._last_sent = {}    # (channel, subject) -> ts
        self._suppressed = {}   # (channel, subject) -> count of cooldown-skipped sends
        self._bg_started = False

    def _within_cooldown(self, key):
        now = time.monotonic()
        last = self._last_sent.get(key)
        return last is not None and (now - last) < self.cooldown

    def _is_night(self):
        now = time.localtime()
        cur = now.tm_hour * 60 + now.tm_min
        sh, sm = map(int, self.night_start.split(":"))
        eh, em = map(int, self.night_end.split(":"))
        start, end, t = sh * 60 + sm, eh * 60 + em, cur
        if start <= end:
            return start <= t < end
        return t >= start or t < end  # window crosses midnight

    @staticmethod
    def _bump(sev):
        order = ["info", "low", "medium", "high", "critical"]
        i = order.index(sev) if sev in order else 2
        return order[min(i + 1, len(order) - 1)]

    def send(self, event, category, severity, extra=""):
        if not self.enabled:
            return
        if category.lower() in self.muted:
            return

        night = self._is_night()
        if night and self.night_escalate:
            severity = self._bump(severity)  # any activity at night -> one level up

        if SEVERITY_ORDER.get(severity, 0) < SEVERITY_ORDER.get(self.min_sev, 2):
            return

        # quiet hours: below floor at night -> hold for morning digest
        if night and SEVERITY_ORDER.get(severity, 0) < SEVERITY_ORDER.get(self.night_floor, 3):
            self.store.insert_held_alert(category, severity,
                                         f"{category} from {event.get('src_host', 'local')}",
                                         str(extra)[:300])
            self.logger(f"[alerts] held for digest: {category} ({severity})")
            return

        src = event.get("src_host") or event.get("src_ip") or ""
        src = src if src not in ("", "-", "127.0.0.1", "::1", "local") else f"{self.host} (LOCAL)"
        dst_port = event.get("dst_port", "-")
        when = event.get("local_time") or event.get("ts") or time.strftime("%Y-%m-%d %H:%M:%S")

        sev_emoji = SEVERITY_EMOJI.get(severity, "\U0001f534")
        cat_emoji = CATEGORY_EMOJI.get(category, "\U0001f4a1")
        bar = "\u2500" * 22
        if night:
            bar += "\n\U0001f319 NIGHT MODE: severity escalated"

        e_extra = html.escape(extra) if extra else ""
        e_src = html.escape(str(src))
        msg = (
            f"<b>{sev_emoji} {cat_emoji} {html.escape(category.upper())}</b> "
            f"<i>({severity})</i>\n"
            f"<code>{bar}</code>\n"
            f"\U0001f4bb Host: <b>{html.escape(self.host)}</b>\n"
            f"\U0001f310 Source: <code>{e_src}:{event.get('src_port', '-')}</code>\n"
            f"\U0001f3e2 Target port: <code>{dst_port}</code>\n"
            f"\U0001f4c5 Time: {when}"
        )
        if e_extra:
            msg += f"\n<code>{bar}</code>\n{e_extra}"

        subject = f"OpenCanary [{severity}] {category} from {src}"
        self._dispatch(subject, msg, severity, event, category, src)

        # attach screenshot for critical categories
        if severity in ("high", "critical") and category.lower() in self.shot_categories and \
                self.telegram.get("enabled") and self.telegram.get("bot_token"):
            shot = self._grab_screenshot()
            if shot:
                self.send_photo(shot, caption=f"\U0001f4f8 screenshot @ {category}")

    def _buttons_for(self, category, src, severity):
        if not self.inline_buttons or severity not in ("high", "critical") or not category:
            return None

        def _clip(text, limit=59):
            return text[:limit]

        row = [
            {"text": "\u2705 Ack", "callback_data": "ack"},
            {"text": f"\U0001f507 Mute {category}"[:40], "callback_data": _clip(f"mute:{category}")},
        ]
        keyboard = [row]
        if src and src not in ("", "-", "127.0.0.1", "::1", "local"):
            keyboard.append([
                {"text": f"\U0001f6ab Block {src}", "callback_data": _clip(f"block:{src}")},
            ])
        return {"inline_keyboard": keyboard}

    def _dispatch(self, subject, msg, severity, event, category=None, src=""):
        channels = []
        if self.telegram.get("enabled") and self.telegram.get("bot_token"):
            channels.append(("telegram", self._send_telegram))
        if self.discord.get("enabled") and self.discord.get("webhook_url"):
            channels.append(("discord", self._send_discord))
        if self.slack.get("enabled") and self.slack.get("webhook_url"):
            channels.append(("slack", self._send_slack))
        if self.email.get("enabled") and self.email.get("smtp_host"):
            channels.append(("email", self._send_email))

        tg_buttons = self._buttons_for(category, str(src or ""), severity) if self.inline_buttons else None

        for name, fn in channels:
            key = (name, subject)
            now = time.monotonic()
            last = self._last_sent.get(key)
            if last is not None and now - last < self.cooldown:
                # duplicate inside cooldown -> count it instead of dropping silently
                self._suppressed[key] = self._suppressed.get(key, 0) + 1
                continue
            self._last_sent[key] = now
            n = self._suppressed.pop(key, 0)
            out = msg
            if n >= self.batch_limit:
                out += f"\n\n\u267f +{n} similar alerts suppressed in the last window"
            sent = False
            for attempt in range(1, self.retries + 1):
                try:
                    if name == "telegram" and tg_buttons is not None:
                        self._send_telegram(subject, out, buttons=tg_buttons)
                    else:
                        fn(subject, out)
                    sent = True
                    break
                except Exception as exc:
                    self.logger(f"[alerts] {name} attempt {attempt}/{self.retries} failed: {exc}")
                    time.sleep(min(2 * attempt, 5))
            if sent:
                self.store.insert_alert(name, subject, event.get("_id"))
                self.logger(f"[alerts] sent {name} alert: {subject}")
            else:
                self.logger(f"[alerts] {name} DROPPED after {self.retries} attempts: {subject}")

    # ---- background loops: batch flusher + daily digest ----

    def start_background(self):
        if self._bg_started:
            return
        self._bg_started = True
        threading.Thread(target=self._flush_loop, daemon=True).start()
        threading.Thread(target=self._digest_loop, daemon=True).start()

    def _flush_loop(self):
        while True:
            time.sleep(60)
            now = time.monotonic()
            stale = [(k, n) for k, n in list(self._suppressed.items())
                     if now - self._last_sent.get(k, 0) >= self.batch_window and n > 0]
            for key, n in stale:
                self._suppressed.pop(key, None)
                chan = key[0]
                text = (f"\u267f BATCH: {n} duplicate alerts "
                        f"({html.escape(key[1].split(' from ')[0])}) were suppressed.")
                try:
                    if chan == "telegram":
                        self.send_raw(text)
                        self.logger(f"[alerts] batch summary sent ({n}x)")
                except Exception as exc:
                    self.logger(f"[alerts] batch flush failed: {exc}")

    def _digest_loop(self):
        while True:
            try:
                dh, dm = map(int, self.digest_time.split(":"))
                now = time.localtime()
                target = time.mktime((now.tm_year, now.tm_mon, now.tm_mday, dh, dm, 0, 0, 0, -1))
                if target <= time.time():
                    target += 86400
                time.sleep(min(target - time.time(), 3600))
                if time.time() >= target:
                    self.send_digest()
            except Exception as exc:
                self.logger(f"[alerts] digest loop error: {exc}")
                time.sleep(300)

    def send_digest(self):
        """Morning summary: what happened in the last 24h."""
        try:
            cats = self.store.counts_by_category(24)
            sevs = dict(self.store.counts_by_severity(24))
            ips = self.store.top_ips(3, 24)
            held = self.store.drain_held_alerts()
            fails = self.store.failed_logins(24)
            total = sum(n for _, n in cats)
            lines = [
                "\U0001f4ca <b>DAILY DIGEST - last 24h</b>",
                "<code>" + "\u2500" * 22 + "</code>",
                f"\U0001f4c8 Total events: <b>{total}</b>  |  critical: <b>{sevs.get('critical', 0)}</b>  high: <b>{sevs.get('high', 0)}</b>",
            ]
            top = sorted(cats, key=lambda x: -x[1])[:6]
            for c, n in top:
                lines.append(f"  \u2022 {html.escape(c)}: {n}")
            if fails:
                lines.append(f"\U0001f512 Failed logins (24h): {fails}")
            if ips:
                lines.append("\U0001f310 Top sources: " + ", ".join(
                    f"{html.escape(ip[0])}({ip[1]})" for ip in ips))
            if held:
                lines.append(f"\U0001f319 Night-held alerts: {len(held)}")
                for h in held[:10]:
                    lines.append(f"  \u2022 [{h['severity']}] {html.escape(h['category'])} @ {h['ts']}")
            else:
                lines.append("\U0001f319 Night-held alerts: 0")
            self.send_raw("\n".join(lines))
            self.logger("[alerts] daily digest sent")
        except Exception as exc:
            self.logger(f"[alerts] digest failed: {exc}")

    # ---- screenshots ----

    def _grab_screenshot(self):
        try:
            from PIL import ImageGrab
            import io
            img = ImageGrab.grab()
            buf = io.BytesIO()
            img.convert("RGB").save(buf, format="JPEG", quality=55)
            return buf.getvalue()
        except Exception as exc:
            self.logger(f"[alerts] screenshot failed: {exc}")
            return None

    def send_photo(self, data, caption=""):
        url = f"https://api.telegram.org/bot{self.telegram['bot_token']}/sendPhoto"
        self._http.post(url, data={"chat_id": self.telegram["chat_id"], "caption": caption[:900]},
                        files={"photo": ("shot.jpg", data)}, timeout=20)

    def send_document(self, data, filename="file.bin", caption=""):
        url = f"https://api.telegram.org/bot{self.telegram['bot_token']}/sendDocument"
        self._http.post(url, data={"chat_id": self.telegram["chat_id"], "caption": caption[:900]},
                        files={"document": (filename, data)}, timeout=30)

    def send_raw(self, text):
        """Direct passthrough message (used by dashboard test button)."""
        ok = []
        if self.telegram.get("enabled") and self.telegram.get("bot_token"):
            url = f"https://api.telegram.org/bot{self.telegram['bot_token']}/sendMessage"
            self._http.post(url, json={
                "chat_id": self.telegram["chat_id"],
                "text": text, "parse_mode": "HTML",
            }, timeout=10)
            ok.append("telegram")
        return ok

    def _send_telegram(self, subject, msg, buttons=None):
        url = f"https://api.telegram.org/bot{self.telegram['bot_token']}/sendMessage"
        payload = {"chat_id": self.telegram["chat_id"], "text": msg, "parse_mode": "HTML"}
        if buttons:
            payload["reply_markup"] = buttons
        r = self._http.post(url, json=payload, timeout=10)
        r.raise_for_status()

    def _send_discord(self, subject, msg):
        self._http.post(self.discord["webhook_url"], json={"content": f"**{subject}**\n```\n{msg}\n```"}, timeout=10)

    def _send_slack(self, subject, msg):
        self._http.post(self.slack["webhook_url"], json={"text": f"*{subject}*\n```\n{msg}\n```"}, timeout=10)

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