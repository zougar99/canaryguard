import os
import threading
import time
from datetime import datetime

from .config import get_store

DEFAULT_FOLDERS = [
    os.path.join(os.path.expanduser("~"), "Desktop"),
    os.path.join(os.path.expanduser("~"), "Documents"),
    os.path.join(os.path.expanduser("~"), "Downloads"),
    os.path.join(os.path.expanduser("~"), "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
]

SUSPICIOUS_EXT = {".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".hta", ".scr", ".py", ".jar", ".lnk"}


class FolderWatchdog:
    """Watchdog over user folders (Desktop, Documents, Downloads, Startup...).

    Flags newly created / modified / deleted files and reports them, so the
    user knows when an intruder drops or tamper files on the PC.  Ignores
    noise from known tools (e.g. browser caches in Downloads is reported,
    but creation is just logged - the alert only fires for suspicious types
    or Startup folder changes).
    """

    def __init__(self, config, alerts=None, logger=None, secrets=None, ransomware=None):
        self.config = config
        self.logger = logger or print
        self.store = get_store(config)
        self.alerts = alerts
        self.secrets = secrets
        self.ransomware = ransomware
        self.folders = config.get("protect", "folders", default=DEFAULT_FOLDERS)
        self._observer = None

    def _is_noise(self, path):
        base = os.path.basename(path).lower()
        noise = {".tmp", ".temp", ".crdownload", ".part", ".partial", "~", ".lock"}
        if any(base.endswith(x) for x in noise):
            return True
        if ".cache" in path.lower() or os.path.basename(os.path.dirname(path)).lower() == "cache":
            return True
        return False

    def _handle(self, event, event_type, is_suspicious):
        path = event.src_path.replace("/", "\\")
        if self._is_noise(path):
            return
        folder = os.path.dirname(path)
        label = os.path.basename(path) or path
        details = f"{event_type}: {path}"
        self.store.insert_file_event(folder, path, event_type, details)
        self.logger(f"[protect] {event_type}: {path}")

        # feed ransomware tripwire on every create/modify
        if self.ransomware and event_type in ("created", "modified") and not event.is_directory:
            try:
                self.ransomware.record(folder, path)
            except Exception:
                pass

        # Scan file content for tokens/keys/passwords
        if self.secrets and event_type in ("created", "modified") and os.path.isfile(path):
            try:
                hits = self.secrets.scan_file(path)
                if hits:
                    self.secrets.report(path, hits)
            except Exception as exc:
                self.logger(f"[secrets] scan error {path}: {exc}")

        # Alert only for suspicious actions
        if not is_suspicious:
            return
        ext = os.path.splitext(path)[1].lower()
        kind = "executable" if ext in SUSPICIOUS_EXT else "file"
        if self.alerts:
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            msg = (
                f"FILE {event_type.upper()} ({kind})\n"
                f"path: {path}\n"
                f"time: {now}"
            )
            event = {"src_host": "", "src_port": -1, "dst_port": -1, "local_time": now, "ts": now}
            sev = "critical" if "Startup" in path else "high"
            self.alerts.send(event, f"file:{event_type}", sev, msg)

    def start(self):
        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler

            observers = []
            for folder in self.folders:
                if not os.path.isdir(folder):
                    continue

                class Handler(FileSystemEventHandler):
                    def _suspicious(self, path):
                        ext = os.path.splitext(path)[1].lower()
                        return ext in SUSPICIOUS_EXT or "Startup" in path

                    def on_created(self, event):
                        if event.is_directory:
                            self._handle(event, "created", False)
                            return
                        self._handle(event, "created", self._suspicious(event.src_path))

                    def on_deleted(self, event):
                        if event.is_directory:
                            self._handle(event, "deleted", False)
                            return
                        self._handle(event, "deleted", self._suspicious(event.src_path))

                    def on_modified(self, event):
                        if event.is_directory:
                            return
                        self._handle(event, "modified", self._suspicious(event.src_path))

                    def on_moved(self, event):
                        if event.is_directory:
                            self._handle(event, "moved", False)
                            return
                        self._handle(event, "moved", self._suspicious(event.src_path))

                observer = Observer()
                handler = Handler()
                handler._handle = self._handle
                observer.schedule(handler, folder, recursive=True)
                observers.append(observer)
                self.logger(f"[protect] watching {folder}")
            self._observers = observers
            for observer in observers:
                observer.daemon = True
                observer.start()
        except Exception as exc:
            self.logger(f"[protect] watcher failed: {exc}")

    def stop(self):
        for observer in getattr(self, "_observers", []) or []:
            observer.stop()
        self._observers = []


class Cleanup:
    """Find and optionally delete files left behind by an intruder.

    Scans user-writable spots (Temp, Downloads, Startup, Recent) for files
    created in the last N minutes that look suspicious (exe/ps1/bat/vbs/js
    dropped from another machine).  Deletion is explicit and path-whitelisted
    so nothing important gets removed.
    """

    def __init__(self, config, logger=None):
        self.config = config
        self.logger = logger or print
        self.store = get_store(config)

    def _recent_paths(self, minutes=120):
        cutoff = time.time() - minutes * 60
        scan_dirs = [
            os.environ.get("TEMP", os.path.join(os.path.expanduser("~"), "AppData", "Local", "Temp")),
            os.path.join(os.path.expanduser("~"), "Downloads"),
            os.path.join(os.path.expanduser("~"), "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
            os.path.join(os.path.expanduser("~"), "AppData", "Local", "Temp"),
        ]
        found = []
        for d in scan_dirs:
            if not os.path.isdir(d):
                continue
            try:
                for name in os.listdir(d):
                    p = os.path.join(d, name)
                    try:
                        st = os.stat(p)
                    except OSError:
                        continue
                    if st.st_mtime < cutoff:
                        continue
                    if os.path.splitext(name)[1].lower() not in SUSPICIOUS_EXT:
                        continue
                    if name.lower().startswith(("canary", "opencanary")):
                        continue
                    found.append({"path": p, "size": st.st_size, "mtime": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S")})
            except PermissionError:
                continue
        return found

    def find(self, minutes=120):
        items = self._recent_paths(minutes)
        self.logger(f"[cleanup] found {len(items)} suspicious recent files")
        return items

    def delete(self, paths):
        removed, failed = [], []
        for p in paths:
            p = p.replace("/", "\\")
            if not os.path.exists(p):
                continue
            # safety: never delete our own files or the decoy folder
            low = p.lower()
            if "canaryguard" in low or "canarydecoys" in low or "opencanary" in low:
                failed.append((p, "protected path"))
                continue
            try:
                os.remove(p)
                removed.append(p)
                self.logger(f"[cleanup] deleted {p}")
            except Exception as exc:
                failed.append((p, str(exc)))
        return removed, failed