import os
import threading
import time
from datetime import datetime

import winreg

from .config import get_store

_RUN_KEYS = [
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
]

_STARTUP_FOLDERS = [
    os.path.join(os.path.expanduser("~"), "AppData", "Roaming",
                 "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
]


class PersistenceWatchdog:
    """Detect new startup entries - attacker persistence on the PC.

    Polls Run registry keys and Startup folders every N seconds.
    First scan = baseline (silent). Afterwards any NEW entry triggers
    a high alert: catches added Run keys, dropped LNK files, new
    scheduled tasks basics via Registry only (OpenCanary handles tasks).
    """

    def __init__(self, config, alerts=None, logger=None):
        self.config = config
        self.logger = logger or print
        self.store = get_store(config)
        self.alerts = alerts
        self.poll = float(config.get("persist", "poll_seconds", default=60))
        self._stop = threading.Event()
        self._thread = None
        self._run_keys = set()
        self._startup_files = set()

    # ---- registry scan ----

    def _read_run_keys(self):
        out = set()
        for root, path in _RUN_KEYS:
            try:
                key = winreg.OpenKey(root, path)
                with key:
                    i = 0
                    while True:
                        try:
                            name, _, _ = winreg.EnumValue(key, i)
                            i += 1
                            out.add((str(root), path, name.lower()))
                        except OSError:
                            break
            except OSError:
                continue
        return out

    def _read_startup(self):
        out = set()
        for folder in _STARTUP_FOLDERS:
            if not os.path.isdir(folder):
                continue
            for name in os.listdir(folder):
                if not name.startswith("~"):
                    out.add(name.lower())
        return out

    # ---- monitoring ----

    def _scan(self):
        cur_run = self._read_run_keys()
        cur_start = self._read_startup()
        # check for new registry entries
        for entry in cur_run - self._run_keys:
            self._fire("reg", f"{entry[2]} in {entry[0]}\\{entry[1]}")
        # check for new startup files
        for f in cur_start - self._startup_files:
            self._fire("file", f)
        self._run_keys = cur_run
        self._startup_files = cur_start

    def _fire(self, kind, what):
        self.logger(f"[persist] NEW {kind}: {what}")
        self.store.insert_file_event(
            "persist", what, "created",
            f"new persistence ({kind})"
        )
        if not self.alerts:
            return
        msg = (
            f"\U0001f4a9 PERSISTENCE ENTRY ADDED\n"
            f"type: {kind}\n"
            f"entry: {what}\n"
            f"time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        event = {"src_host": "local", "src_port": -1, "dst_port": -1, "local_time": "", "ts": ""}
        self.alerts.send(event, "persist:new", "high", msg)

    def _run(self):
        try:
            self._run_keys = self._read_run_keys()
            self._startup_files = self._read_startup()
            n = len(self._run_keys) + len(self._startup_files)
            self.logger(f"[persist] baseline: {len(self._run_keys)} reg + {len(self._startup_files)} startup files")
        except Exception as exc:
            self.logger(f"[persist] baseline error: {exc}")
        while not self._stop.is_set():
            time.sleep(self.poll)
            try:
                self._scan()
            except Exception as exc:
                self.logger(f"[persist] scan error: {exc}")

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
