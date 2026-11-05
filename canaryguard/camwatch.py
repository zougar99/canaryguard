import threading
import time
from datetime import datetime

import winreg

from .config import get_store

_BASE = r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"
_KINDS = {"webcam": "camera", "microphone": "mic"}


def _filetime_to_dt(ft):
    return datetime.fromtimestamp((ft - 116444736000000000) / 10_000_000)


def _read_usage(kind_root):
    """Return {(device_subkey, app_path): (start_ft, stop_ft)} for a consent kind."""
    out = {}
    try:
        root = winreg.OpenKey(winreg.HKEY_CURRENT_USER, rf"{_BASE}\{kind_root}")
    except OSError:
        return out
    with root:
        _walk(root, "", out)
        # NonPackaged apps (win32 exes) live in a subkey
        try:
            np = winreg.OpenKey(root, "NonPackaged")
            with np:
                _walk(np, "NonPackaged/", out)
        except OSError:
            pass
    return out


def _walk(key, prefix, out):
    try:
        i = 0
        while True:
            sub = winreg.EnumKey(key, i)
            i += 1
            try:
                sk = winreg.OpenKey(key, sub)
                with sk:
                    vals = {}
                    for name in ("LastUsedTimeStart", "LastUsedTimeStop"):
                        try:
                            vals[name] = winreg.QueryValueEx(sk, name)[0]
                        except OSError:
                            vals[name] = None
                    if "LastUsedTimeStart" in vals and vals["LastUsedTimeStart"]:
                        out[(prefix + sub, )] = (
                            vals.get("LastUsedTimeStart"), vals.get("LastUsedTimeStop"),
                            sub,
                        )
            except OSError:
                continue
    except OSError:
        pass


def device_status():
    """Camera/mic usage snapshot from the ConsentStore registry.

    Returns {"camera": {...}, "microphone": {...}} where each dict has:
      in_use: bool, apps: [{"app": ..., "since": "HH:MM:SS"}], recent_24h: int
    """
    snapshot = {}
    for reg_kind, label in _KINDS.items():
        apps, recent_24h = [], 0
        cutoff = time.time() - 86400
        for entry in _read_usage(reg_kind).values():
            try:
                start, stop, app = entry
            except Exception:
                continue
            try:
                start_dt = _filetime_to_dt(start)
            except Exception:
                start_dt = None
            if start_dt and start_dt.timestamp() >= cutoff:
                recent_24h += 1
            if stop is None or start > stop:   # session open
                apps.append({
                    "app": str(app),
                    "since": start_dt.strftime("%H:%M:%S") if start_dt else "?",
                })
        snapshot[label] = {"in_use": bool(apps), "apps": apps,
                           "recent_24h": recent_24h}
    return snapshot


class CameraMicMonitor:
    """Detect when any application turns on the webcam or microphone.

    Reads the Windows ConsentStore registry (same source the Settings
    privacy page uses). A usage START while nothing was in use fires one
    alert naming the app - catches stalkerware/spy apps.
    """

    def __init__(self, config, alerts=None, logger=None):
        self.config = config
        self.logger = logger or print
        self.store = get_store(config)
        self.alerts = alerts
        self.poll = float(config.get("cam_monitor", "poll_seconds", default=3))
        self.notify = config.get("cam_monitor", "notify", default=True)
        self._stop = threading.Event()
        self._thread = None
        self._active = set()   # (kind, app) currently in use

    def _scan(self):
        for reg_kind, label in _KINDS.items():
            for entry in _read_usage(reg_kind).values():
                start, stop, app = entry
                key = (label, app)
                if stop is None or start > stop:  # session open
                    if key not in self._active:
                        self._active.add(key)
                        self._fire(label, app, start)
                else:
                    self._active.discard(key)

    def _fire(self, kind, app, start_ft):
        when = "?"
        try:
            when = _filetime_to_dt(start_ft).strftime("%H:%M:%S")
        except Exception:
            pass
        self.store.insert_cam_event(kind, app, f"started at {when}")
        icon = "\U0001f4f8" if kind == "camera" else "\U0001f3a4"
        self.logger(f"[cam] {icon} {kind.upper()} IN USE by {app} (since {when})")
        if not self.alerts or not self.notify:
            return
        msg = (
            f"{icon} {kind.upper()} ACTIVATED\n"
            f"app: {app}\n"
            f"since: {when}\n"
            f"time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        event = {"src_host": "local", "src_port": -1, "dst_port": -1, "local_time": "", "ts": ""}
        self.alerts.send(event, "cam:on" if kind == "camera" else "mic:on", "medium", msg)

    def _run(self):
        # first pass = baseline (mark already-active as seen without firing)
        try:
            self._scan_baseline()
        except Exception as exc:
            self.logger(f"[cam] baseline error: {exc}")
        while not self._stop.is_set():
            time.sleep(self.poll)
            try:
                self._scan()
            except Exception as exc:
                self.logger(f"[cam] error: {exc}")

    def _scan_baseline(self):
        for reg_kind, label in _KINDS.items():
            for entry in _read_usage(reg_kind).values():
                start, stop, app = entry
                if stop is None or start > stop:
                    self._active.add((label, app))

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self.logger("[cam] watching camera & microphone")

    def stop(self):
        self._stop.set()