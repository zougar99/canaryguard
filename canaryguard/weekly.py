"""Weekly recap — a Sunday-evening "this week in numbers" Telegram message.

Independent from the morning digest: this one is the slow-read summary for a
quiet moment (default Sunday 20:00), not an alert. Sends only to Telegram
(the channel everyone actually reads).

State file ``weekly.state`` holds the ISO week already sent, so a restart on
the same evening never sends a duplicate. Delete the file to force a resend.
"""

import os
import threading
import time
from datetime import datetime

from .config import get_store

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE_FILE = os.path.join(BASE, "weekly.state")

_DAYS = {
    "monday": 0, "tuesday": 1, "wednesday": 2, "thursday": 3,
    "friday": 4, "saturday": 5, "sunday": 6,
    "mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6,
    "0": 0, "1": 1, "2": 2, "3": 3, "4": 4, "5": 5, "6": 6,
}


class WeeklyRecap:
    """Send the weekly numbers summary once a week, at most once per ISO week."""

    def __init__(self, config, alerts, logger=None):
        self.config = config
        self.alerts = alerts
        self.logger = logger or print
        cfg = config.section("weekly_digest")
        self.enabled = bool(cfg.get("enabled", True))
        day = str(cfg.get("day", "sunday")).strip().lower() or "sunday"
        self.day = _DAYS.get(day, 6)
        try:
            self.hour, self.minute = (int(x) for x in str(cfg.get("time", "20:00")).split(":", 1))
        except Exception:
            self.hour, self.minute = 20, 0
        self.poll = max(15.0, float(cfg.get("poll_seconds", 60)))
        self.store = get_store(config)
        self._thread = None

    # ---------------- internals ----------------

    @staticmethod
    def _week_key(now):
        return now.strftime("%G-W%V")

    def _sent_week(self):
        try:
            with open(STATE_FILE, encoding="utf-8") as fh:
                return fh.read().strip()
        except Exception:
            return None

    def _mark_sent(self):
        try:
            with open(STATE_FILE, "w", encoding="utf-8") as fh:
                fh.write(self._week_key(datetime.now()))
        except Exception as exc:
            self.logger(f"[weekly] cannot write state file: {exc}")

    def _due(self, now):
        if now.weekday() != self.day:
            return False
        if (now.hour, now.minute) < (self.hour, self.minute):
            return False
        return self._sent_week() != self._week_key(now)

    def _loop(self):
        while True:
            try:
                now = datetime.now()
                if self._due(now):
                    self.send()
                    self._mark_sent()
            except Exception as exc:
                self.logger(f"[weekly] loop error: {exc}")
            time.sleep(self.poll)

    # ---------------- public API ----------------

    def start(self):
        if not self.enabled:
            self.logger("[weekly] disabled by config")
            return
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="weekly-recap")
        self._thread.start()
        self.logger(f"[weekly] recap armed: {next(k for k, v in _DAYS.items() if v == self.day)} "
                    f"{self.hour:02d}:{self.minute:02d}")

    def build_message(self):
        """Plain-HTML message summarising the last 7 days."""
        hours = 7 * 24
        cats = self.store.counts_by_category(hours)
        total = sum(n for _, n in cats)
        sevs = dict(self.store.counts_by_severity(hours))
        criticals, highs = sevs.get("critical", 0), sevs.get("high", 0)
        uniq = self.store.unique_ips(7)
        ips = self.store.top_ips(5, hours)
        fails = self.store.failed_logins(hours)
        top = sorted(cats, key=lambda x: -x[1])[:6]
        bar = "\u2500" * 22

        lines = [
            "<b>\U0001f4c5 WEEKLY RECAP</b> \u2014 last 7 days",
            "<code>" + bar + "</code>",
            f"\U0001f4c8 Total events: <b>{total}</b>  (critical <b>{criticals}</b>, high <b>{highs}</b>)",
            f"\U0001f310 Unique attackers: <b>{uniq}</b>",
        ]
        if top:
            lines.append("\U0001f3af Most hit:")
            lines += [f"  \u2022 {c}: {n}" for c, n in top]
        if ips:
            lines.append("\U0001f455 Top sources:")
            lines += [f"  \u2022 <code>{i}</code> ({n} events)" for i, n in ips]
        if fails:
            lines.append(f"\U0001f512 Failed logins (7d): {fails}")
        good = ("\U0001f6e1 no critical hits this week" if criticals == 0
                else "\U0001f6a8 criticals this week — review the details above")
        lines.append(good)
        lines.append("<i>change day/time in weekly_digest config section</i>")
        return "\n".join(lines)

    def send(self):
        try:
            msg = self.build_message()
        except Exception as exc:
            self.logger(f"[weekly] could not build recap: {exc}")
            return False
        try:
            self.alerts.send_raw(msg)
            self.logger("[weekly] recap sent")
            return True
        except Exception as exc:
            self.logger(f"[weekly] recap failed: {exc}")
            return False
