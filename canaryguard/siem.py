import json
import socket
import threading
import time

import requests

from .config import get_store


class SIEMForwarder:
    def __init__(self, config, logger=None):
        self.config = config
        self.logger = logger or print
        self.store = get_store(config)
        cfg = config.section("siem")
        self.es = cfg.get("elasticsearch", {})
        self.splunk = cfg.get("splunk", {})
        self.http = cfg.get("http", {})
        self.syslog = cfg.get("syslog", {})
        self._queue = []
        self._lock = threading.Lock()
        self._stop = threading.Event()

    def start(self):
        threading.Thread(target=self._worker, daemon=True).start()

    def stop(self):
        self._stop.set()

    def push(self, event):
        with self._lock:
            self._queue.append(event)

    def _worker(self):
        while not self._stop.is_set():
            with self._lock:
                batch, self._queue = self._queue[:50], []
            for ev in batch:
                try:
                    self._forward(ev)
                except Exception as exc:
                    self.logger(f"[siem] forward error: {exc}")
            time.sleep(2)

    def _forward(self, event):
        if self.es.get("enabled") and self.es.get("url"):
            self._to_elasticsearch(event)
        if self.splunk.get("enabled") and self.splunk.get("hec_url"):
            self._to_splunk(event)
        if self.http.get("enabled") and self.http.get("url"):
            self._to_http(event)
        if self.syslog.get("enabled"):
            self._to_syslog(event)

    def _to_elasticsearch(self, event):
        index = self.es.get("index", "opencanary-events")
        url = f"{self.es['url'].rstrip('/')}/{index}/_doc"
        requests.post(url, json=event, timeout=10)

    def _to_splunk(self, event):
        url = self.splunk["hec_url"].rstrip("/")
        requests.post(
            f"{url}/services/collector/event",
            headers={"Authorization": f"Splunk {self.splunk['token']}"},
            json={"event": event, "sourcetype": "opencanary", "index": "main"},
            timeout=10,
        )

    def _to_http(self, event):
        requests.post(self.http["url"], json=event, headers=self.http.get("headers", {}), timeout=10)

    def _to_syslog(self, event):
        msg = f"<14>opencanaryd {json.dumps(event, ensure_ascii=False)}"
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(msg.encode("utf-8", "replace"), (self.syslog["host"], self.syslog["port"]))
        sock.close()