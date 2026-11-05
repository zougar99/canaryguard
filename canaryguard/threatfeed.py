"""Threat-intel priors — A11 from the roadmap.

Optional, opt-in: load known-bad IP lists (one IP or CIDR per line, '#'
comments) from <home>/feeds/*.txt or from URLs in config `threatintel.feeds`.
Hits are cached in the SQLite feed_ips table and used to enrich alerts and
incidents. Disabled by default; no network calls unless you add URLs.
"""

import ipaddress
import os
import threading

from .paths import home


class ThreatIntel:
    def __init__(self, config, store=None, logger=None):
        from .config import get_store

        self.config = config
        self.logger = logger or print
        if store is None:
            try:
                store = get_store(config)
            except Exception:
                store = None
        self.store = store
        cfg = config.section("threatintel")
        self.enabled = bool(cfg.get("enabled", False))
        self.feed_urls = list(cfg.get("feeds", []) or [])
        self.feeds_dir = os.path.join(home(), "feeds")
        self._ips = set()
        self._networks = []
        self._loaded = False
        self._lock = threading.Lock()

    # ---- loading ----

    def _iter_feed_lines(self):
        # local files
        if os.path.isdir(self.feeds_dir):
            for name in sorted(os.listdir(self.feeds_dir)):
                if not name.endswith((".txt", ".lst", ".dat")):
                    continue
                path = os.path.join(self.feeds_dir, name)
                try:
                    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                        for line in fh:
                            yield name, line
                except Exception as exc:
                    self.logger(f"[threatintel] cannot read {path}: {exc}")
        # remote feeds (only when explicitly configured)
        if self.feed_urls:
            try:
                import requests
            except Exception:
                self.logger("[threatintel] 'requests' unavailable — skipping URL feeds")
                return
            for url in self.feed_urls:
                try:
                    resp = requests.get(url, timeout=30)
                    resp.raise_for_status()
                    for line in resp.text.splitlines():
                        yield os.path.basename(url) or "url-feed", line
                except Exception as exc:
                    self.logger(f"[threatintel] feed {url} failed: {exc}")

    def refresh(self):
        """Reload all feeds into memory + SQLite cache. Returns stats."""
        ips, networks = set(), []
        entries = []
        for source, raw in self._iter_feed_lines():
            line = raw.strip().split()[0] if raw.strip() else ""
            if not line or line.startswith("#"):
                continue
            if "/" in line:
                try:
                    networks.append((ipaddress.ip_network(line, strict=False), source))
                    continue
                except ValueError:
                    continue
            try:
                ipaddress.ip_address(line)
            except ValueError:
                continue
            ips.add(line)
            entries.append((line, source))
        with self._lock:
            self._ips = ips
            self._networks = networks
            self._loaded = True
        # fold sources per IP for the DB cache
        if self.store is not None:
            by_ip = {}
            for ip, source in entries:
                by_ip.setdefault(ip, set()).add(source)
            try:
                self.store.replace_feed_ips((ip, ",".join(sorted(srcs))) for ip, srcs in by_ip.items())
            except Exception as exc:
                self.logger(f"[threatintel] cache write failed: {exc}")
        stats = {"ips": len(ips), "networks": len(networks), "sources": len(entries)}
        self.logger(f"[threatintel] loaded {stats}")
        return stats

    # ---- lookup ----

    def _ensure_loaded(self):
        if not self._loaded:
            self.refresh()

    def lookup(self, ip):
        if not self.enabled or not ip:
            return {"listed": False, "sources": []}
        self._ensure_loaded()
        with self._lock:
            if ip in self._ips:
                return {"listed": True, "sources": ["feeds"]}
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                return {"listed": False, "sources": []}
            hits = [src for net, src in self._networks if addr in net]
            if hits:
                return {"listed": True, "sources": sorted(set(hits))}
        # fall back to the SQLite cache (e.g. feeds refreshed on another run)
        if self.store is not None:
            cached = self.store.feed_lookup(ip)
            if cached:
                return {"listed": True, "sources": cached.split(",")}
        return {"listed": False, "sources": []}
