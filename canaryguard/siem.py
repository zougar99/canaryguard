import json
import re
import socket
import threading
import time
from collections import deque

import requests

from .config import get_store

_SECRET_KEY_RE = re.compile(r"(password|passwd|secret|token|api[_-]?key|key|credential)", re.I)


def _scrub(value):
    """Recursively replace values of secret-looking keys with [REDACTED]."""
    if isinstance(value, dict):
        return {k: ("[REDACTED]" if _SECRET_KEY_RE.search(str(k)) else _scrub(v))
                for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub(v) for v in value]
    return value


class SIEMForwarder:
    """Buffered SIEM fan-out.

    Bounded in-memory queue (drop-oldest) so a dead SIEM endpoint can never
    exhaust memory. Secrets are scrubbed before leaving the box by default —
    captured credentials must not ride along into log platforms.
    """

    def __init__(self, config, logger=None):
        self.config = config
        self.logger = logger or print
        self.store = get_store(config)
        cfg = config.section("siem")
        self.es = cfg.get("elasticsearch", {})
        self.splunk = cfg.get("splunk", {})
        self.http = cfg.get("http", {})
        self.syslog = cfg.get("syslog", {})
        self.max_queue = int(cfg.get("max_queue", 1000))
        self.scrub = bool(cfg.get("scrub_secrets", True))
        self.verify_tls = bool(cfg.get("verify_tls", True))
        self._queue = deque(maxlen=self.max_queue)
        self._drops = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()

    def start(self):
        threading.Thread(target=self._worker, daemon=True).start()

    def stop(self):
        self._stop.set()

    def push(self, event):
        with self._lock:
            if len(self._queue) == self._queue.maxlen:
                self._drops += 1
                if self._drops == 1 or self._drops % 100 == 0:
                    self.logger(f"[siem] queue full ({self.max_queue}) — dropped {self._drops} oldest event(s)")
            self._queue.append(event)

    @property
    def drop_count(self):
        return self._drops

    def _prepare(self, event):
        return _scrub(event) if self.scrub else event

    def _worker(self):
        while not self._stop.is_set():
            with self._lock:
                batch = [self._queue.popleft() for _ in range(min(50, len(self._queue)))]
            for ev in batch:
                try:
                    self._forward(ev)
                except Exception as exc:
                    self.logger(f"[siem] forward error: {exc}")
            time.sleep(2)

    def _forward(self, event):
        payload = self._prepare(event)
        if self.es.get("enabled") and self.es.get("url"):
            self._to_elasticsearch(payload)
        if self.splunk.get("enabled") and self.splunk.get("hec_url"):
            self._to_splunk(payload)
        if self.http.get("enabled") and self.http.get("url"):
            self._to_http(payload)
        if self.syslog.get("enabled"):
            self._to_syslog(payload)

    def _to_elasticsearch(self, event):
        index = self.es.get("index", "opencanary-events")
        url = f"{self.es['url'].rstrip('/')}/{index}/_doc"
        verify = self.es.get("verify_tls", self.verify_tls)
        requests.post(url, json=event, timeout=10, verify=verify)

    def _to_splunk(self, event):
        url = self.splunk["hec_url"].rstrip("/")
        requests.post(
            f"{url}/services/collector/event",
            headers={"Authorization": f"Splunk {self.splunk['token']}"},
            json={"event": event, "sourcetype": "opencanary", "index": "main"},
            timeout=10,
            verify=self.splunk.get("verify_tls", self.verify_tls),
        )

    def _to_http(self, event):
        requests.post(self.http["url"], json=event,
                      headers=self.http.get("headers", {}),
                      timeout=10,
                      verify=self.http.get("verify_tls", self.verify_tls))

    def _to_syslog(self, event):
        msg = f"<14>opencanaryd {json.dumps(event, ensure_ascii=False)}"
        host = self.syslog.get("host", "127.0.0.1")
        port = int(self.syslog.get("port", 514))
        protocol = str(self.syslog.get("protocol", "udp")).lower()
        if protocol == "tcp":
            with socket.create_connection((host, port), timeout=5) as sock:
                sock.sendall((msg + "\n").encode("utf-8", "replace"))
            return
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.sendto(msg.encode("utf-8", "replace"), (host, port))
        finally:
            sock.close()
