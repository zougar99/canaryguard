import threading
import time
from datetime import datetime

from .config import get_store

try:
    import psutil
except ImportError:
    psutil = None

DEFAULT_IGNORE = {
    "system", "system idle process", "registry", "memory compression",
    "svchost.exe", "csrss.exe", "dwm.exe", "winlogon.exe", "services.exe",
    "lsass.exe", "smss.exe", "wininit.exe", "fontdrvhost.exe", "sihost.exe",
    "taskhostw.exe", "explorer.exe", "runtimebroker.exe", "conhost.exe",
    "dllhost.exe", "audiodg.exe", "searchindexer.exe", "searchapp.exe",
    "startmenuexperiencehost.exe", "shellexperiencehost.exe",
    "applicationframehost.exe", "textinputhost.exe", "widgets.exe",
    "msmpeng.exe", "securityhealthservice.exe", "securityhealthsystray.exe",
    "spoolsv.exe", "ctfmon.exe", "wudfhost.exe", "dashost.exe",
    "wmiprvse.exe", "wmiapsrv.exe", "compattelrunner.exe", "smartscreen.exe",
    "backgroundtaskhost.exe", "python.exe", "pythonw.exe", "pwsh.exe",
    "powershell.exe", "cmd.exe", "openconsole.exe", "windowsterminal.exe",
    "nissrv.exe", "msdtc.exe", "sgrmbroker.exe", "aggregatorhost.exe",
}


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class ProcessMonitor:
    """Poll the OS process list and report applications that start or exit.

    The first snapshot is a silent baseline, so nothing already running at
    startup generates alerts. Afterwards every new process is recorded, and
    (unless ignored) triggers a Telegram alert; exited processes likewise.
    """

    def __init__(self, config, alerts=None, logger=None):
        self.config = config
        self.logger = logger or print
        self.store = get_store(config)
        self.alerts = alerts
        self.poll = float(config.get("process_monitor", "poll_seconds", default=3))
        self.notify_start = config.get("process_monitor", "notify_start", default=True)
        self.notify_exit = config.get("process_monitor", "notify_exit", default=True)
        self.cooldown = int(config.get("process_monitor", "cooldown_seconds", default=30))
        extra = set(config.get("process_monitor", "ignore", default=[]))
        self.ignore = DEFAULT_IGNORE | {x.lower() for x in extra}
        self._stop = threading.Event()
        self._thread = None
        self._last = {}
        self._cooldown = {}

    # ---------- snapshot helpers ----------

    def _snapshot(self):
        snap = {}
        for proc in psutil.process_iter(["pid", "name", "exe", "username", "create_time"]):
            try:
                info = proc.info
                snap[info["pid"]] = {
                    "name": (info["name"] or "?").lower(),
                    "exe": info["exe"] or "",
                    "user": info["username"] or "",
                    "created": info["create_time"] or 0,
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return snap

    def _within_cooldown(self, key):
        now = time.monotonic()
        return (now - self._cooldown.get(key, 0)) < self.cooldown

    def _record(self, ev_type, pid, info):
        name = info["name"]
        path = info["exe"] or "(unknown)"
        user = info["user"]
        now = _now()
        details = f"{ev_type}: {name} pid={pid} user={user}"
        self.store.insert_process_event(ev_type, name, pid, path, user, details)
        label = "APP OPENED" if ev_type == "started" else "APP CLOSED"
        self.logger(f"[procs] {label}: {name} (pid={pid})")

        if not self.alerts:
            return
        if ev_type == "started" and not self.notify_start:
            return
        if ev_type == "exited" and not self.notify_exit:
            return
        if self._within_cooldown(f"{ev_type}:{name}"):
            return
        self._cooldown[f"{ev_type}:{name}"] = time.monotonic()

        icon = "\U0001f680" if ev_type == "started" else "\U0001f6aa"
        msg = (
            f"{icon} {label}\n"
            f"app: {name}\n"
            f"path: {path}\n"
            f"user: {user or 'local'}\n"
            f"time: {now}"
        )
        event = {"src_host": "local", "src_port": -1, "dst_port": -1, "local_time": now, "ts": now}
        self.alerts.send(event, f"proc:{'start' if ev_type == 'started' else 'exit'}", "medium", msg)

    # ---------- loop ----------

    def _run(self):
        self._last = self._snapshot()   # silent baseline
        self.logger(f"[procs] baseline: {len(self._last)} processes running")
        while not self._stop.is_set():
            try:
                snap = self._snapshot()
                for pid in sorted(set(snap) - set(self._last)):
                    info = snap[pid]
                    if info["name"] not in self.ignore:
                        self._record("started", pid, info)
                    else:
                        self.logger(f"[procs] started (ignored): {info['name']} (pid={pid})")
                for pid in sorted(set(self._last) - set(snap)):
                    info = self._last[pid]
                    if info["name"] not in self.ignore:
                        self._record("exited", pid, info)
                    else:
                        self.logger(f"[procs] exited (ignored): {info['name']} (pid={pid})")
                self._last = snap
            except Exception as exc:
                self.logger(f"[procs] error: {exc}")
            self._stop.wait(self.poll)

    def start(self):
        if psutil is None:
            self.logger("[procs] psutil missing - process monitor disabled")
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self.logger("[procs] monitoring application start/exit")

    def stop(self):
        self._stop.set()