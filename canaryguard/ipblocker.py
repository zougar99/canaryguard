import os
import threading
import time
from datetime import datetime

from .config import get_store


class IPBlocker:
    """Auto-block IPs after repeated failed access attempts.

    Counts failed sessions per source IP; when a threshold is reached
    within a window, creates a Windows Firewall inbound block rule
    (BLOCK_DURATION minutes, auto-removed after expiry). Catches
    brute-force attackers.
    """

    def __init__(self, config, alerts=None, logger=None):
        self.config = config
        self.logger = logger or print
        self.store = get_store(config)
        self.alerts = alerts
        cfg = config.section("ipblock")
        self.enabled = cfg.get("enabled", True)
        self.max_fails = int(cfg.get("max_fails", 5))
        self.window = float(cfg.get("window_seconds", 300))
        self.block_duration = int(cfg.get("block_minutes", 60)) * 60
        self.prefix = "CanaryBlock"
        self._failures = {}    # ip -> [timestamps]
        self._blocked = {}     # ip -> expiry_time
        self._lock = threading.Lock()

    def register_fail(self, ip):
        if not self.enabled or not ip or ip in ("127.0.0.1", "::1", "?", ""):
            return
        now = time.monotonic()
        with self._lock:
            fails = self._failures.setdefault(ip, [])
            fails[:] = [t for t in fails if now - t < self.window]
            fails.append(now)
            if len(fails) >= self.max_fails and ip not in self._blocked:
                self._blocked[ip] = now + self.block_duration
                self._failures.pop(ip, None)
                self._block(ip, len(fails))

    def _block(self, ip, count):
        rule = f'{self.prefix}_{ip.replace(".", "_")}'
        cmd = (
            f'netsh advfirewall firewall add rule name="{rule}" '
            f'dir=in action=block remoteip={ip} enable=yes'
        )
        ok = os.system(cmd) == 0
        status = "BLOCKED" if ok else "BLOCK FAILED"
        self.logger(f"[ipblock] {ip} {status} ({count} fails)")
        self.store.insert_event(
            time.strftime("%Y-%m-%d %H:%M:%S"),
            "ipblock", ip, -1, -1, "ip:blocked", "high",
            {"detail": f"blocked {ip} after {count} fails"}
        )
        if self.alerts:
            msg = (
                f"\U0001f6ab IP BLOCKED: {ip}\n"
                f"reason: {count} failed attempts in {self.window//60:.0f} min\n"
                f"duration: {self.block_duration//3600}h\n"
                f"time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )
            event = {"src_host": ip, "src_port": -1, "dst_port": -1, "local_time": "", "ts": ""}
            self.alerts.send(event, "ip:blocked", "high", msg)

    def cleanup_loop(self):
        """Remove expired rules periodically."""
        while True:
            time.sleep(60)
            now = time.monotonic()
            with self._lock:
                expired = [ip for ip, exp in self._blocked.items() if exp <= now]
                for ip in expired:
                    del self._blocked[ip]
                    rule = f'{self.prefix}_{ip.replace(".", "_")}'
                    os.system(
                        f'netsh advfirewall firewall delete rule name="{rule}"'
                    )
                    self.logger(f"[ipblock] rule removed for {ip}")
