import os
import threading
import time
from datetime import datetime

import psutil

from .config import get_store

_BROWSER_FILES = {"login data", "cookies", "local state", "logindata-journal"}


class BrowserCredsWatch:
    """Alert when an unknown process reads browser credential databases.

    Polls open file handles via psutil every few seconds. If any
    non-browser process (Chrome, Firefox, Edge, Brave) has the
    Login Data / Cookies / Local State file open → CRITICAL alert.
    Attacker tools copying browser creds get caught red-handed.
    """

    BROWSER_PROCS = {
        "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe",
        "msedgewebview2.exe",
    }

    def __init__(self, config, alerts=None, logger=None):
        self.config = config
        self.logger = logger or print
        self.store = get_store(config)
        self.alerts = alerts
        self.poll = float(config.get("browser", "poll_seconds", default=5))
        self._stop = threading.Event()
        self._seen = set()  # (pid, filepath) already alerted
        self._cd = {}

    def _scan(self):
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                name = proc.info["name"].lower()
                if name in self.BROWSER_PROCS:
                    continue
                for f in proc.open_files():
                    path = f.path.lower()
                    fname = os.path.basename(path)
                    if fname in _BROWSER_FILES:
                        key = (proc.info["pid"], path)
                        if key in self._seen:
                            continue
                        self._seen.add(key)
                        self._alert(proc.info["pid"], name, f.path)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        # prune old entries to prevent memory growth
        if len(self._seen) > 2000:
            self._seen.clear()

    def _alert(self, pid, proc_name, filepath):
        fname = os.path.basename(filepath)
        self.store.insert_file_event(
            "browser", filepath, "accessed",
            f"{proc_name} (pid={pid}) opened {fname}"
        )
        self.logger(f"[browser] \U0001f575 {proc_name} reading {fname}!")
        if not self.alerts:
            return
        msg = (
            f"\U0001f575\ufe0f BROWSER CREDS ACCESS\n"
            f"process: {proc_name} (pid={pid})\n"
            f"file: {filepath}\n"
            f"time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        event = {"src_host": "local", "src_port": -1, "dst_port": -1, "local_time": "", "ts": ""}
        self.alerts.send(event, "browser:creds", "critical", msg)

    def _run(self):
        while not self._stop.is_set():
            time.sleep(self.poll)
            try:
                self._scan()
            except Exception as exc:
                self.logger(f"[browser] error: {exc}")

    def start(self):
        threading.Thread(target=self._run, daemon=True).start()
        self.logger("[browser] watching browser credential files")

    def stop(self):
        self._stop.set()
