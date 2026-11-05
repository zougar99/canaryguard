import os
import time
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from .config import get_store

ARCHIVE_EXT = {".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2"}


class _Handler(FileSystemEventHandler):
    def __init__(self, monitor):
        self.monitor = monitor

    def on_created(self, ev):
        try:
            if not ev.is_directory:
                self.monitor._check(ev.src_path)
        except Exception as exc:
            self.monitor.logger(f"[staging] handler error: {exc}")

    on_modified = on_created


class StagingDetector:
    """Alert when a large archive is created - attacker staging data.

    Attacker compresses Documents/Downloads before exfiltrating.
    Files >= min_size_mb with archive extensions trigger a high alert.
    """

    def __init__(self, config, alerts=None, logger=None):
        self.config = config
        self.logger = logger or print
        self.store = get_store(config)
        self.alerts = alerts
        cfg = config.section("staging")
        self.min_size = int(cfg.get("min_size_mb", 10)) * 1_048_576
        folders = cfg.get("folders", None) or ["Documents", "Downloads", "Desktop"]
        self.folders = [
            os.path.join(os.path.expanduser("~"), f)
            for f in folders if os.path.isdir(os.path.join(os.path.expanduser("~"), f))
        ]
        self._obs = None
        self._cd = {}

    def _check(self, path):
        try:
            ext = "." + path.rsplit(".", 1)[-1].lower() if "." in path else ""
            if ext not in ARCHIVE_EXT:
                return
            if self._within(f"stg:{path.lower()}"):
                return
            sz = os.path.getsize(path)
            if sz < self.min_size:
                return
            self.store.insert_file_event(
                os.path.dirname(path), path, "created",
                f"staging archive {sz/1048576:.1f} MB"
            )
            self.logger(f"[staging] \U0001f5dc large archive: {path} ({sz/1048576:.1f} MB)")
            if not self.alerts:
                return
            msg = (
                f"\U0001f5dc STAGING ARCHIVE DETECTED\n"
                f"file: {path}\n"
                f"size: {sz/1048576:.1f} MB\n"
                f"time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )
            event = {"src_host": "local", "src_port": -1, "dst_port": -1, "local_time": "", "ts": ""}
            self.alerts.send(event, "staging:archive", "high", msg)
        except Exception as exc:
            self.logger(f"[staging] check error: {exc}")

    def _within(self, key):
        now = time.monotonic()
        last = self._cd.get(key)
        if last is not None and now - last < 30:
            return True
        self._cd[key] = now
        return False

    def start(self):
        self._obs = Observer(timeout=1)
        handler = _Handler(self)
        scheduled = 0
        for folder in self.folders:
            try:
                self._obs.schedule(handler, folder, recursive=True)
                scheduled += 1
            except Exception as exc:
                self.logger(f"[staging] watch failed for {folder}: {exc}")
        self._obs.daemon = True
        self._obs.start()
        self.logger(f"[staging] watching {scheduled} folders for large archives")

    def stop(self):
        if self._obs:
            self._obs.stop()
            self._obs.join(timeout=2)
