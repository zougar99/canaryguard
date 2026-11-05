import re
import subprocess
import threading
import time
from datetime import datetime

from .config import get_store

INTERFACE_RE = re.compile(r"Name\s*:\s*(.+)")
SSID_RE = re.compile(r"SSID\s*:\s*(\S.*\S|\S)\s*$")
BSSID_RE = re.compile(r"BSSID\s*:\s*([0-9a-fA-F:]{17})")
STATE_RE = re.compile(r"State\s*:\s*(\S.*\S)\s*$")


class WiFiEvilTwinWatch:
    """Detect rogue Wi-Fi changes: SSID/BSSID switch or connect to an
    unknown network. Catches evil-twin access points and attacker hotspots
    like 'Free_WiFi' next to a coffee shop.

    BSSID = MAC of the actual AP radio. If the PC silently roams to a
    different BSSID with the same SSID, that's an evil twin - CRITICAL.
    """

    def __init__(self, config, alerts=None, logger=None):
        self.config = config
        self.logger = logger or print
        self.store = get_store(config)
        self.alerts = alerts
        cfg = config.section("wifiwatch")
        self.enabled = cfg.get("enabled", True)
        self.poll = float(cfg.get("poll_seconds", 20))
        self.notify_connect = bool(cfg.get("notify_connect", True))
        self.known_ssids = {s.lower() for s in (cfg.get("known_ssids", []) or [])}
        self._stop = threading.Event()
        self._ssid = None
        self._bssid = None
        self._known = False

    # ---- netsh parsing ----

    def _read(self):
        """Return {ifname: (state, ssid, bssid)} for all WLAN interfaces."""
        try:
            out = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True, timeout=10, encoding="utf-8", errors="replace",
            ).stdout
        except Exception:
            return {}
        result = {}
        cur = None
        for line in out.splitlines():
            m = INTERFACE_RE.match(line.strip())
            if m and "wlan" in m.group(1).lower():
                cur = m.group(1).strip()
                result[cur] = ("", None, None)
                continue
            if cur is None:
                continue
            m = STATE_RE.search(line)
            if m:
                result[cur] = (m.group(1).lower(), result[cur][1], result[cur][2])
                continue
            m = SSID_RE.search(line)
            if m and m.group(1):
                result[cur] = (result[cur][0], m.group(1), result[cur][2])
                continue
            m = BSSID_RE.search(line)
            if m:
                result[cur] = (result[cur][0], result[cur][1], m.group(1).lower())
        return result

    # ---- core ----

    def _fire(self, category, severity, why, raw=None):
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        self.store.insert_event(
            ts, "wifi", "local", -1, -1, category, severity, {"detail": why})
        self.logger(f"[wifi] \U0001f4e1 {why}")
        if not self.alerts:
            return
        event = {"src_host": "local", "src_port": "-", "dst_port": "-",
                 "local_time": ts, "ts": ""}
        self.alerts.send(event, category, severity,
                         f"\U0001f4e1 WI-FI {category.upper()}\n{why}\ntime: {ts}")

    def _check(self):
        interfaces = self._read()
        for ifname, (state, ssid, bssid) in interfaces.items():
            if not state:
                continue
            if "disconnected" in state:
                if self._ssid and self.notify_connect:
                    self._fire("lan:new", "low",
                               f"wi-fi disconnected (was on '{self._ssid}')")
                self._ssid = None
                self._bssid = None
                self._known = False
                continue
            if "connected" not in state:
                continue
            # first read: baseline silently
            if self._ssid is None:
                self._ssid = ssid
                self._bssid = bssid
                self._known = ssid and ssid.lower() in self.known_ssids
                self.logger(f"[wifi] baseline: '{ssid}' (bssid={bssid}, known={self._known})")
                continue
            if ssid != self._ssid:
                self._fire("lan:new", "medium",
                           f"network CHANGED: '{self._ssid}' -> '{ssid}'")
                self._known = ssid and ssid.lower() in self.known_ssids
            elif bssid and self._bssid and bssid != self._bssid:
                self._fire("lan:new", "high",
                           f"POSSIBLE EVIL TWIN! same SSID '{ssid}' but "
                           f"AP MAC changed {self._bssid} -> {bssid}")
            elif ssid and not self._known:
                self._fire("lan:new", "medium",
                           f"connected to UNKNOWN network '{ssid}' "
                           f"(not in known_ssids)")
            self._ssid = ssid
            self._bssid = bssid or self._bssid

    def _run(self):
        while not self._stop.is_set():
            try:
                self._check()
            except Exception as exc:
                self.logger(f"[wifi] error: {exc}")
            self._stop.wait(self.poll)

    def start(self):
        if not self.enabled:
            return
        threading.Thread(target=self._run, daemon=True).start()
        self.logger("[wifi] evil-twin watch running")

    def stop(self):
        self._stop.set()
