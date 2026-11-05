import hashlib
import os
import threading
import time
from datetime import datetime

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from .config import get_store

DANGEROUS_EXT = {".exe", ".scr", ".bat", ".cmd", ".msi", ".com", ".pif",
                 ".vbs", ".js", ".jar", ".ps1", ".hta", ".lnk"}


def _sha256(path, chunk=1 << 20):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for part in iter(lambda: fh.read(chunk), b""):
                h.update(part)
        return h.hexdigest()
    except Exception:
        return "?"


class _Handler(FileSystemEventHandler):
    def __init__(self, outer):
        self.outer = outer

    def on_created(self, ev):
        if ev.is_directory:
            return
        self.outer._check(ev.src_path)

    on_moved = on_created


class DownloadsSentinel:
    """Alert when a dangerous executable lands in the Downloads folder.

    Computes SHA-256 and includes it in the alert so it can be checked
    against VirusTotal manually (or automatically with an API key).
    """

    def __init__(self, config, alerts=None, logger=None):
        self.config = config
        self.logger = logger or print
        self.store = get_store(config)
        self.alerts = alerts
        self.folder = config.get("downloads_monitor", "folder",
                                 default=os.path.join(os.path.expanduser("~"), "Downloads"))
        self.notify = config.get("downloads_monitor", "notify", default=True)
        extra = set(config.get("downloads_monitor", "extensions", default=[]))
        self.exts = {e.lower() for e in DANGEROUS_EXT} | {e.lower() for e in extra}
        self._stop = threading.Event()
        self._obs = None
        self._cd = {}

    def _within(self, key):
        now = time.monotonic()
        if now - self._cd.get(key, 0) < 30:
            return True
        self._cd[key] = now
        return False

    def _check(self, path):
        ext = "." + path.rsplit(".", 1)[-1].lower() if "." in path else ""
        if ext not in self.exts or self._within(f"dl:{path.lower()}"):
            return
        time.sleep(0.5)  # let the writer finish
        digest = _sha256(path)
        short = digest[:16] + ("..." if len(digest) > 16 else "")
        self.store.insert_file_event("Downloads", path, "downloaded", f"sha256={short}")
        self.logger(f"[dl] EXECUTABLE DOWNLOADED: {path} ({short})")
        if not self.alerts or not self.notify:
            return
        msg = (
            f"\u2b07\ufe0f EXECUTABLE DOWNLOADED\n"
            f"file: {path}\n"
            f"sha256: {digest}\n"
            f"time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        event = {"src_host": "local", "src_port": -1, "dst_port": -1, "local_time": "", "ts": ""}
        self.alerts.send(event, "dl:file", "high", msg)

    def start(self):
        if not self.folder or not os.path.isdir(self.folder):
            self.folder = os.path.join(os.path.expanduser("~"), "Downloads")
        try:
            self._obs = Observer(timeout=1)
            self._obs.schedule(_Handler(self), self.folder, recursive=False)
            self._obs.daemon = True
            self._obs.start()
            self.logger(f"[dl] watching downloads: {self.folder}")
        except Exception as exc:
            self.logger(f"[dl] watcher failed ({self.folder}): {exc}")
            self._obs = None

    def stop(self):
        if self._obs:
            self._obs.stop()
            self._obs.join(timeout=2)