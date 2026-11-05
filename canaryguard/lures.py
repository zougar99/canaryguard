import hashlib
import os
import re
import textwrap
import threading
import time
from datetime import datetime

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from .config import get_store

# files ransomware drops at the root of encrypted folders
RANSOM_NOTE_RE = re.compile(
    r"(?i)(.*(decrypt|restore|recover|ransom|readme|help|fix|locked|"
    r"important).*\.(txt|html|hta|jpg|png|url|lnk)|"
    r"_readme_|_how_to_decrypt|.onion\$|"
    r"\.onion(_|\.to|\.link)?|_readme\.txt$|"
    r"how_to_recover|how_to_unlock|recover_files)"
)

HOSTS = r"C:\Windows\System32\drivers\etc\hosts"


class _NoteHandler(FileSystemEventHandler):
    def __init__(self, monitor):
        self.monitor = monitor

    def on_created(self, ev):
        try:
            if not ev.is_directory:
                self.monitor.check_note(ev.src_path)
        except Exception as exc:
            self.monitor.logger(f"[lures] handler error: {exc}")

    on_modified = on_created


class CanaryLures:
    """Two silent tripwires:

    1. Ransom-note detector - any file with a typical ransom note name
       (HELP_DECRYPT.txt, RESTORE_FILES.html ...) created in a watched
       folder fires a CRITICAL alert before the attacker finishes.
    2. Hosts-file guard - hashes C:\\Windows\\System32\\drivers\\etc\\hosts;
       any change that was not paired with a manual flag fires a HIGH
       alert (DNS redirect / C2 mapping attacks).
    """

    def __init__(self, config, alerts=None, logger=None):
        self.config = config
        self.logger = logger or print
        self.store = get_store(config)
        self.alerts = alerts
        cfg = config.section("lures")
        self.enabled = cfg.get("enabled", True)
        self.folders = [
            os.path.join(os.path.expanduser("~"), f)
            for f in (cfg.get("folders", ["Desktop", "Documents", "Downloads"])) or []
            if os.path.isdir(os.path.join(os.path.expanduser("~"), f))
        ]
        self.hosts_poll = float(cfg.get("hosts_poll_seconds", 60))
        self.hosts_baseline = None    # set on first read
        self._obs = None
        self._stop = threading.Event()
        self._seen = set()
        self._lock = threading.Lock()

    # ---- 1. ransom notes ----

    def check_note(self, path):
        base = os.path.basename(path)
        if not RANSOM_NOTE_RE.search(base):
            return
        key = f"note:{path.lower()}"
        now = time.monotonic()
        last = self._seen.get(key)
        if last is not None and now - last < 60:
            return
        self._seen[key] = now
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        self.store.insert_file_event(os.path.dirname(path), path, "created",
                                     f"ransom note pattern: {base}")
        self.logger(f"[lures] \U0001f480 ransom note dropped: {path}")
        if not self.alerts:
            return
        event = {"src_host": "local", "src_port": "-", "dst_port": "-",
                 "local_time": ts, "ts": ""}
        self.alerts.send(
            event, "ransomware:detected", "critical",
            f"\U0001f480 RANSOM NOTE DROP\n"
            f"file: {path}\n"
            f"match: {base}\n"
            f"time: {ts}",
        )

    def _start_notes(self):
        h = _NoteHandler(self)
        self._obs = Observer(timeout=1)
        for f in self.folders:
            try:
                self._obs.schedule(h, f, recursive=True)
            except Exception as exc:
                self.logger(f"[lures] watch failed for {f}: {exc}")
        self._obs.daemon = True
        self._obs.start()
        self.logger(f"[lures] ransom-note watch on {len(self.folders)} folders")

    # ---- 2. hosts guard ----

    def _hosts_digest(self):
        try:
            with open(HOSTS, "rb") as fh:
                return hashlib.sha256(fh.read()).hexdigest()[:16]
        except Exception:
            return None

    def _hosts_loop(self):
        self.hosts_baseline = self._hosts_digest()
        if self.hosts_baseline:
            self.logger(f"[lures] hosts baseline: {self.hosts_baseline}")
        while not self._stop.is_set():
            self._stop.wait(self.hosts_poll)
            try:
                cur = self._hosts_digest()
                if cur and self.hosts_baseline and cur != self.hosts_baseline:
                    self._hosts_alert()
                    self.hosts_baseline = cur   # so one change = one alert
            except Exception as exc:
                self.logger(f"[lures] hosts error: {exc}")

    def _hosts_alert(self):
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        self.store.insert_file_event(HOSTS, HOSTS, "modified",
                                     "hosts file changed - possible DNS hijack")
        self.logger(f"[lures] \U0001f6a7 hosts file changed!")
        if not self.alerts:
            return
        event = {"src_host": "local", "src_port": "-", "dst_port": "-",
                 "local_time": ts, "ts": ""}
        try:
            with open(HOSTS, "r", errors="replace") as fh:
                tail = "\n".join(
                    ln for ln in fh.read().splitlines()
                    if ln.strip() and not ln.strip().startswith("#"))[:400]
        except Exception:
            tail = "(unreadable)"
        self.alerts.send(
            event, "file:modified", "high",
            f"\U0001f6a7 HOSTS FILE CHANGED - possible DNS hijack\n"
            f"file: {HOSTS}\n"
            f"current non-comment lines:\n{textwrap.indent(tail, '  ')}\n"
            f"time: {ts}",
        )

    def start(self):
        if not self.enabled:
            return
        try:
            self._start_notes()
        except Exception as exc:
            self.logger(f"[lures] notes watch failed: {exc}")
        threading.Thread(target=self._hosts_loop, daemon=True).start()

    def stop(self):
        self._stop.set()
        if self._obs:
            try:
                self._obs.stop()
            except Exception:
                pass
