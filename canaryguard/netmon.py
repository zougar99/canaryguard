import ipaddress
import threading
import time
from datetime import datetime

from .config import get_store

try:
    import psutil
except ImportError:
    psutil = None

DEFAULT_IGNORE = {
    "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe",
    "svchost.exe", "explorer.exe", "runtimebroker.exe", "python.exe",
    "pythonw.exe", "pwsh.exe", "powershell.exe", "cmd.exe", "conhost.exe",
    "msmpeng.exe", "nissrv.exe", "searchapp.exe", "widgets.exe",
    "dllhost.exe", "sihost.exe", "taskhostw.exe", "spoolsv.exe",
    "smartscreen.exe", "securityhealthservice.exe", "securityhealthsystray.exe",
    "onedrive.exe", "steam.exe", "spotify.exe", "discord.exe", "telegram.exe",
    "searchindexer.exe", "msdtc.exe", "wudfhost.exe", "dashost.exe",
}


def _is_external(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved:
        return False
    return True


class NetworkMonitor:
    """Detect NEW outbound internet connections per process.

    Silent baseline on start; afterwards every (process, remote ip:port)
    pair never seen before is recorded, and unknown applications (not in
    the ignore list) trigger a Telegram alert - catches reverse shells,
    malware phoning home, or an intruder exfiltrating data.
    """

    def __init__(self, config, alerts=None, logger=None):
        self.config = config
        self.logger = logger or print
        self.store = get_store(config)
        self.alerts = alerts
        self.poll = float(config.get("netmon", "poll_seconds", default=5))
        self.cooldown = int(config.get("netmon", "cooldown_seconds", default=60))
        extra = set(config.get("netmon", "ignore", default=[]))
        self.ignore = DEFAULT_IGNORE | {x.lower() for x in extra}
        self.notify = config.get("netmon", "notify", default=True)
        self._stop = threading.Event()
        self._thread = None
        self._seen = set()
        self._cd = {}

    def _within(self, key):
        now = time.monotonic()
        last = self._cd.get(key)
        if last is not None and now - last < self.cooldown:
            return True
        self._cd[key] = now
        return False

    def _proc_name(self, pid):
        try:
            return psutil.Process(pid).name().lower()
        except Exception:
            return "?"

    def _scan(self):
        for conn in psutil.net_connections(kind="inet"):
            if conn.status != "ESTABLISHED" or not conn.raddr:
                continue
            rip, rport = conn.raddr.ip, conn.raddr.port
            if not _is_external(rip):
                continue
            key = (conn.pid, rip, rport)
            if key in self._seen:
                continue
            self._seen.add(key)
            name = self._proc_name(conn.pid)
            details = f"{name} -> {rip}:{rport}"
            self.store.insert_net_event(name or "?", conn.pid or -1, f"{rip}:{rport}", details)
            if name in self.ignore:
                continue
            self.logger(f"[net] NEW outbound: {details}")
            if not self.alerts or not self.notify:
                continue
            if self._within(f"net:{name}:{rip}"):
                continue
            msg = (
                f"\U0001f310 NEW OUTBOUND CONNECTION\n"
                f"app: {name}\n"
                f"remote: {rip}:{rport}\n"
                f"time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )
            event = {"src_host": "local", "src_port": -1, "dst_port": rport,
                     "local_time": "", "ts": ""}
            self.alerts.send(event, "net:new", "medium", msg)

    def _run(self):
        try:
            self._scan()   # silent baseline
            self.logger(f"[net] baseline: {len(self._seen)} connections")
        except Exception as exc:
            self.logger(f"[net] baseline error: {exc}")
        while not self._stop.is_set():
            try:
                self._scan()
            except Exception as exc:
                self.logger(f"[net] error: {exc}")
            self._stop.wait(self.poll)

    def start(self):
        if psutil is None:
            self.logger("[net] psutil missing - network monitor disabled")
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self.logger("[net] monitoring outbound connections")

    def stop(self):
        self._stop.set()