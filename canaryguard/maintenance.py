"""Retention & maintenance — D4 from the roadmap.

Deletes rows older than the configured per-table retention and optionally
VACUUMs. Runs once at startup and then every `interval_hours`.
"""

import threading
import time

from .logstore import RETENTION_TABLES, get_logstore

DEFAULT_DAYS = {
    "events": 180,
    "alerts": 180,
    "creds": 180,
    "sessions": 180,
    "keystrokes": 30,
    "file_events": 90,
    "secret_hits": 180,
    "process_events": 60,
    "usb_events": 365,
    "clipboard_events": 30,
    "net_events": 60,
    "cam_events": 90,
    "token_trips": 365,
    "feedback": 365,
}


class RetentionJob:
    def __init__(self, config, store=None, logger=None):
        self.config = config
        self.logger = logger or print
        self.store = store or get_logstore(config.get("opencanary", "db_file"))
        cfg = config.section("retention")
        self.enabled = bool(cfg.get("enabled", True))
        self.interval_hours = float(cfg.get("interval_hours", 24))
        self.vacuum = bool(cfg.get("vacuum", False))
        custom = cfg.get("days", {}) or {}
        self.days = {**DEFAULT_DAYS, **{k: int(v) for k, v in custom.items()}}
        self._stop = threading.Event()
        self._thread = None

    def run_once(self):
        total = 0
        for table in RETENTION_TABLES:
            days = self.days.get(table)
            if not days or days <= 0:
                continue  # 0 or negative disables a table
            try:
                deleted = self.store.purge_older_than(table, days)
                if deleted:
                    self.logger(f"[retention] {table}: purged {deleted} row(s) older than {days}d")
                    total += deleted
            except Exception as exc:
                self.logger(f"[retention] {table}: {exc}")
        if self.vacuum:
            try:
                self.store.vacuum()
                self.logger("[retention] VACUUM + WAL checkpoint done")
            except Exception as exc:
                self.logger(f"[retention] vacuum failed: {exc}")
        return total

    def start(self):
        if not self.enabled:
            self.logger("[retention] disabled")
            return
        def _loop():
            try:
                self.run_once()
            except Exception as exc:
                self.logger(f"[retention] initial pass failed: {exc}")
            while not self._stop.wait(self.interval_hours * 3600):
                try:
                    self.run_once()
                except Exception as exc:
                    self.logger(f"[retention] pass failed: {exc}")
        self._thread = threading.Thread(target=_loop, daemon=True)
        self._thread.start()
        self.logger(f"[retention] armed (every {self.interval_hours}h)")

    def stop(self):
        self._stop.set()
