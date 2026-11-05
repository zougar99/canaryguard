import re
import subprocess
import threading
import time
from datetime import datetime

from .config import get_store

_MAC_RE = re.compile(r"((?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2})", re.I)


class PhoneProximity:
    """Know when your phone is home.

    Tracks one MAC (your phone) in the ARP table:
    - phone disappears for > away_minutes  -> alert "phone left" + optional PC lock
    - phone reappears                      -> alert "phone back"

    Set the MAC once in config phone.phone_mac. Empty MAC = disabled.
    """

    def __init__(self, config, alerts=None, logger=None):
        self.config = config
        self.logger = logger or print
        self.store = get_store(config)
        self.alerts = alerts
        cfg = config.section("phone")
        self.enabled = cfg.get("enabled", True)
        self.mac = (cfg.get("phone_mac", "") or "").lower().replace("-", ":")
        self.poll = float(cfg.get("poll_seconds", 30))
        self.away_sec = float(cfg.get("away_minutes", 3)) * 60
        self.lock_when_away = bool(cfg.get("lock_when_away", False))
        self._stop = threading.Event()
        self._present = None   # None unknown until first scan
        self._last_seen = None

    def _arp_visible(self):
        try:
            out = subprocess.run(["arp", "-a"], capture_output=True,
                                 timeout=10, encoding="utf-8", errors="replace").stdout
        except Exception:
            return False
        return self.mac in out.lower().replace("-", ":")

    def _fire(self, category, severity, msg):
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        self.store.insert_event(ts, "phone", "local", -1, -1,
                                category, severity, {"detail": msg})
        self.logger(f"[phone] \U0001f4f1 {msg}")
        if not self.alerts:
            return
        event = {"src_host": "local", "src_port": "-", "dst_port": "-",
                 "local_time": ts, "ts": ""}
        self.alerts.send(event, category, severity,
                         f"\U0001f4f1 PHONE PROXIMITY\n{msg}\ntime: {ts}")

    def _run(self):
        if not self.mac:
            self.logger("[phone] disabled (no phone_mac set in config)")
            return
        self.logger(f"[phone] proximity guard for {self.mac}")
        while not self._stop.is_set():
            try:
                here = self._arp_visible()
                now = time.time()
                if here:
                    self._last_seen = now
                    if self._present is False:
                        self._fire("lan:new", "low", "phone is BACK (Wi-Fi range)")
                    self._present = True
                elif self._present:
                    if (now - (self._last_seen or now)) > self.away_sec:
                        self._present = False
                        away = int((now - (self._last_seen or now)) / 60)
                        self._fire("session", "medium",
                                   f"phone LEFT Wi-Fi range ({away} min ago)",
                                   )
                        if self.lock_when_away:
                            from .panic import lock_workstation
                            lock_workstation()
            except Exception as exc:
                self.logger(f"[phone] error: {exc}")
            self._stop.wait(self.poll)

    def start(self):
        if not self.enabled:
            return
        threading.Thread(target=self._run, daemon=True).start()

    def stop(self):
        self._stop.set()
