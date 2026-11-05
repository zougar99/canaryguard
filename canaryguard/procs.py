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
        self.rarity_pairs = None
        if config.get("process_monitor", "rarity_alerts", default=True):
            try:
                from .processgraph import ProcessPairModel

                self.rarity_pairs = ProcessPairModel(
                    config, store=self.store,
                    warmup=int(config.get("process_monitor", "rarity_warmup", default=200)),
                )
            except Exception as exc:
                self.logger(f"[procs] parent-child rarity unavailable: {exc}")
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

        # enrich: command line + parent process (best effort)
        cmd = ""
        parent = ""
        try:
            proc = psutil.Process(pid)
            cl = proc.cmdline()
            cmd = " ".join(cl)[:200] if cl else ""
            ppid = proc.ppid()
            parent = psutil.Process(ppid).name() if ppid else ""
        except Exception:
            pass

        details = f"{ev_type}: {name} pid={pid} user={user}"
        if parent:
            details += f" parent={parent}"
        if cmd:
            details += f" cmd={cmd[:120]}"
        self.store.insert_process_event(ev_type, name, pid, path, user, details)

        # B1: never-seen parent->child pair (living-off-the-land signal)
        if ev_type == "started" and self.rarity_pairs and parent:
            try:
                obs = self.rarity_pairs.observe(parent, name)
                if obs and obs["is_rare"]:
                    self._alert_rare_pair(obs, user, pid, cmd)
            except Exception as exc:
                self.logger(f"[procs] pair rarity error: {exc}")
        label = "APP OPENED" if ev_type == "started" else "APP CLOSED"
        self.logger(f"[procs] {label}: {name} (pid={pid})" + (f" parent={parent}" if parent else ""))

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
        lines = [f"app: {name}", f"path: {path}", f"user: {user or 'local'}"]
        if parent:
            lines.append(f"parent: {parent}")
        if cmd:
            lines.append(f"cmd: {cmd[:150]}")
        lines.append(f"time: {now}")
        msg = (
            f"{icon} {label}\n" + "\n".join(lines)
        )
        event = {"src_host": "local", "src_port": -1, "dst_port": -1, "local_time": now, "ts": now}
        self.alerts.send(event, f"proc:{'start' if ev_type == 'started' else 'exit'}", "medium", msg)

    def _alert_rare_pair(self, obs, user, pid, cmd):
        self.logger(f"[procs] RARE PAIR: {obs['pair']} (never seen before)")
        if not self.alerts:
            return
        now = _now()
        lines = [f"pair: {obs['pair']}", f"user: {user or 'local'}", f"pid: {pid}"]
        if cmd:
            lines.append(f"cmd: {cmd[:150]}")
        lines.append("this parent->child combination has never been observed on this host")
        lines.append(f"time: {now}")
        event = {"src_host": "local", "src_port": -1, "dst_port": -1, "local_time": now, "ts": now}
        self.alerts.send(event, "proc:rare_parent", "high", "\n".join(lines))

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