import threading
import time

import requests

from .config import get_store

_IPAPI = "http://ip-api.com/json/{ip}?fields=status,country,regionName,city,org,query"
_LOCAL = ("127.0.0.1", "::1", "0.0.0.0", "localhost")


class GeoLocator:
    """GeoIP lookups with cache, fallback and rate limiting (ip-api free tier)."""

    def __init__(self, config, enabled=True, min_interval=1.0):
        self.store = get_store(config)
        self.enabled = enabled
        self.min_interval = min_interval
        self._last_call = 0.0
        self._lock = threading.Lock()

    def is_local(self, ip):
        if not ip or ip in _LOCAL:
            return True
        if ip.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                          "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                          "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                          "172.30.", "172.31.", "169.254.", "127.")):
            return True
        return False

    def lookup(self, ip):
        if not self.enabled or not ip or self.is_local(ip):
            return {"country": "", "region": "", "city": "", "org": ""}
        cached = self.store.ip_meta(ip)
        if cached:
            return cached

        with self._lock:
            wait = self.min_interval - (time.monotonic() - self._last_call)
            if wait > 0:
                time.sleep(wait)
            self._last_call = time.monotonic()
            try:
                resp = requests.get(_IPAPI.format(ip=ip), timeout=6)
                data = resp.json()
            except Exception:
                return {"country": "", "region": "", "city": "", "org": ""}

        if data.get("status") != "success":
            return {"country": "", "region": "", "city": "", "org": ""}

        meta = {
            "country": data.get("country", ""),
            "region": data.get("regionName", ""),
            "city": data.get("city", ""),
            "org": data.get("org", ""),
        }
        self.store.upsert_ip_meta(ip, meta["country"], meta["region"], meta["city"], meta["org"])
        return meta