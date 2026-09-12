import os
import sqlite3
import threading
import time
import zipfile
from datetime import datetime

from .config import get_store


class EvidenceBackup:
    """Daily off-site backup of alerts.db as Telegram document.

    Zips the database and uploads it via Telegram sendDocument. Even if
    the attacker wipes the PC, the evidence chain survives in your
    Telegram chat history. Configurable time (default 02:00).
    """

    def __init__(self, config, alerts=None, logger=None):
        self.config = config
        self.logger = logger or print
        self.store = get_store(config)
        self.alerts = alerts
        cfg = config.section("evidence")
        self.enabled = cfg.get("enabled", True)
        self.time = cfg.get("time", "02:00")
        self.max_mb = int(cfg.get("max_mb", 10))
        self.db_file = config.get("opencanary", "db_file")
        if not self.db_file:
            raise RuntimeError("[evidence] no opencanary.db_file configured")

    def _run(self):
        while True:
            try:
                h, m = map(int, self.time.split(":"))
                now = time.localtime()
                target = time.mktime(
                    (now.tm_year, now.tm_mon, now.tm_mday, h, m, 0, 0, 0, -1)
                )
                if target <= time.time():
                    target += 86400
                time.sleep(min(target - time.time(), 3600))
                if time.time() >= target:
                    self._backup()
            except Exception as exc:
                self.logger(f"[evidence] error: {exc}")
                time.sleep(300)

    def _backup(self):
        if not self.alerts:
            return
        try:
            ts = time.strftime("%Y%m%d_%H%M%S")
            zip_path = f"evidence_{ts}.zip"
            with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("canaryguard.db", self._compact())
            data = open(zip_path, "rb").read()
            if len(data) > self.max_mb * 1_048_576:
                self.logger(f"[evidence] compact backup too large ({len(data)//1048576} MB), skipping")
                os.remove(zip_path)
                return
            self.alerts.send_document(
                data,
                filename=os.path.basename(zip_path),
                caption=f"\U0001f4c2 evidence backup {ts} ({len(data)//1024} KB)",
            )
            os.remove(zip_path)
            self.logger(f"[evidence] backup sent ({len(data)//1024} KB)")
        except Exception as exc:
            self.logger(f"[evidence] backup failed: {exc}")

    def _compact(self):
        """Export a lean copy of the DB (schema + last 90 days of events, all creds/alerts)."""
        import sqlite3
        import tempfile

        tmp = tempfile.mktemp(suffix=".db")
        try:
            src = sqlite3.connect(self.db_file, check_same_thread=False)
            dst = sqlite3.connect(tmp)
            src.backup(dst)
            dst.execute("DELETE FROM events WHERE ts < datetime('now', '-90 days')")
            dst.commit()
            dst.close()
            src.close()
            with open(tmp, "rb") as fh:
                return fh.read()
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)

    def start(self):
        if self.enabled:
            threading.Thread(target=self._run, daemon=True).start()
            self.logger(f"[evidence] daily backup at {self.time}")

    def stop(self):
        pass
