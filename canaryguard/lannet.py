import re
import subprocess
import threading
import time
from datetime import datetime

from .config import get_store

_MAC_RE = re.compile(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}")


def _arp_entries():
    """Return {mac_upper: ip} from the local ARP table."""
    out = {}
    try:
        res = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10)
        for line in res.stdout.splitlines():
            m = _MAC_RE.search(line)
            if not m:
                continue
            mac = m.group(0).upper().replace("-", ":")
            parts = line.split()
            ip = next((p for p in parts if p.count(".") == 3), None)
            if ip and mac != "FF:FF:FF:FF:FF:FF":
                out[mac] = ip
    except Exception:
        pass
    return out


class WiFiDeviceMonitor:
    """Alert when a NEW device joins the local network (ARP-based).

    Silent baseline on first scan; afterwards any unseen MAC address
    triggers a high-severity alert - catches neighbors freeloading,
    rogue devices, or an attacker plugged into your network.
    """

    def __init__(self, config, alerts=None, logger=None):
        self.config = config
        self.logger = logger or print
        self.store = get_store(config)
        self.alerts = alerts
        self.poll = float(config.get("lan_monitor", "poll_seconds", default=60))
        self.notify = config.get("lan_monitor", "notify", default=True)
        known = set(config.get("lan_monitor", "known_macs", default=[]))
        self.known = {m.upper().replace("-", ":") for m in known}
        self._stop = threading.Event()
        self._thread = None
        self._seen = set()

    def _handle_new(self, mac, ip):
        self.store.insert_net_event("lan-device", -1, ip or "?", f"new device MAC={mac}")
        self.logger(f"[lan] NEW DEVICE: {mac} @ {ip}")
        if not self.alerts or not self.notify:
            return
        msg = (
            f"\U0001f4f6 NEW DEVICE ON YOUR NETWORK\n"
            f"mac: {mac}\n"
            f"ip: {ip or '?'}\n"
            f"time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        event = {"src_host": ip or mac, "src_port": -1, "dst_port": -1, "local_time": "", "ts": ""}
        self.alerts.send(event, "lan:new", "high", msg)

    def _run(self):
        first = _arp_entries()
        self._seen = set(first) | self.known
        self.logger(f"[lan] baseline: {len(self._seen)} known devices")
        while not self._stop.is_set():
            time.sleep(self.poll)
            try:
                for mac, ip in _arp_entries().items():
                    if mac not in self._seen:
                        self._seen.add(mac)
                        self._handle_new(mac, ip)
            except Exception as exc:
                self.logger(f"[lan] error: {exc}")

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self.logger("[lan] monitoring network for new devices")

    def stop(self):
        self._stop.set()