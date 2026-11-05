import os
import time

from ._winproc import run as _proc_run
from datetime import datetime

from .config import get_store


class RansomwareTripwire:
    """Detect mass file modifications typical of ransomware encryption.

    Fed events from the folder watchdog. A sliding window per folder:
    >threshold files created/modified within <window seconds in the
    same folder triggers a CRITICAL alert + optional network kill.
    """

    def __init__(self, config, alerts=None, logger=None):
        self.config = config
        self.logger = logger or print
        self.store = get_store(config)
        self.alerts = alerts
        cfg = config.section("ransomware")
        self.threshold = int(cfg.get("threshold", 40))
        self.window = float(cfg.get("window_seconds", 60))
        self.kill_net = cfg.get("kill_network", False)
        self.adapter = cfg.get("network_adapter", "Wi-Fi")
        self._events = {}  # folder -> [timestamps]
        self._lock = __import__("threading").Lock()

    def record(self, folder, path=""):
        now = time.monotonic()
        key = os.path.normpath(folder).lower()
        with self._lock:
            evs = self._events.setdefault(key, [])
            evs[:] = [t for t in evs if now - t < self.window]
            evs.append(now)
            count = len(evs)
            if count >= self.threshold:
                self._events.pop(key, None)
                self._fire(key, count)

    def _fire(self, folder, count):
        self.store.insert_event(
            time.strftime("%Y-%m-%d %H:%M:%S"),
            "ransomware", "local", -1, -1,
            "ransomware:detected", "critical",
            {"detail": f"mass modifications in {folder}"},
        )
        self.logger(f"\U0001f6a8 [ransomware] {count} files modified in {folder}!")
        if self.kill_net:
            self._kill_network()
        if not self.alerts:
            return
        event = {"src_host": "local", "src_port": -1, "dst_port": -1, "local_time": "", "ts": ""}
        self.alerts.send(event, "ransomware:detected", "critical",
            f"\U0001f6a8 RANSOMWARE PATTERN\n"
            f"folder: {folder}\n"
            f"files modified: {count} in {int(self.window)}s\n"
            f"network: {'KILLED' if self.kill_net else 'monitoring only'}\n"
            f"time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )

    def _kill_network(self):
        try:
            _proc_run(["netsh", "interface", "set", "interface",
                      self.adapter, "disable"],
                     capture_output=True, timeout=10)
            self.logger(f"[ransomware] network killed ({self.adapter})")
        except Exception as exc:
            self.logger(f"[ransomware] net kill failed: {exc}")
