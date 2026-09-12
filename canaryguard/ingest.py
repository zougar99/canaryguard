import json
import os
import threading
import time

from .alerts import AlertManager
from .classifier import AttackProfiler, classify
from .config import get_store
from .geolocate import GeoLocator
from .honeytokens import HoneytokenManager
from .siem import SIEMForwarder

STATE_FILE = "C:\\Users\\werlist99\\canaryguard\\canaryguard\\ingest_state.json"


class Ingestor:
    def __init__(self, config, logger=None, ipblock=None):
        self.config = config
        self.logger = logger or print
        self.store = get_store(config)
        cfg = config.section("ingest")
        self.poll = cfg.get("poll_seconds", 2)
        self.start_from_end = cfg.get("start_from_end", True)
        self.log_file = config.get("opencanary", "log_file")
        self.geo = GeoLocator(config, enabled=config.section("alerts").get("geoip", True))
        self.alerts = AlertManager(config, logger=logger)
        self.ipblock = ipblock
        self.siem = SIEMForwarder(config, logger=logger)
        self.honeytokens = HoneytokenManager(config, self.alerts, self.geo, logger=logger)
        self.profiler = AttackProfiler()
        self._offset = None
        self._stop = threading.Event()
        self._load_state()

    _FAIL_CATEGORIES = {"brute_force", "web_login_attack", "database_attack", "auth:fail", "shell_command"}

    def _load_state(self):
        try:
            if os.path.exists(STATE_FILE):
                with open(STATE_FILE, "r", encoding="utf-8") as fh:
                    state = json.load(fh)
                if state.get("log_file") == self.log_file:
                    self._offset = state.get("offset")
        except Exception:
            self._offset = None

    def _save_state(self):
        try:
            with open(STATE_FILE, "w", encoding="utf-8") as fh:
                json.dump({"log_file": self.log_file, "offset": self._offset}, fh)
        except Exception:
            pass

    def start(self):
        self.siem.start()
        threading.Thread(target=self._run, daemon=True).start()

    def stop(self):
        self._stop.set()
        self.siem.stop()

    def _tail(self, handle):
        """Yield new lines appended after the current offset."""
        if self._offset is None:
            if self.start_from_end:
                handle.seek(0, os.SEEK_END)
            else:
                handle.seek(0)
            self._offset = handle.tell()
        else:
            handle.seek(self._offset)

        while True:
            line = handle.readline()
            if line:
                self._offset = handle.tell()
                yield line
            else:
                break

    def _run(self):
        self.logger(f"[ingest] tailing {self.log_file}")
        while not self._stop.is_set():
            try:
                if not os.path.exists(self.log_file):
                    time.sleep(self.poll)
                    continue
                with open(self.log_file, "r", encoding="utf-8", errors="replace") as fh:
                    for line in self._tail(fh):
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            event = json.loads(line)
                        except ValueError:
                            continue
                        self._process(event)
                self._save_state()
            except Exception as exc:
                self.logger(f"[ingest] error: {exc}")
            time.sleep(self.poll)

    def _process(self, event):
        category, service, severity, creds, _ = classify(event)
        if category is None:
            return

        src = event.get("src_host") or event.get("src_ip") or ""
        dst_port = event.get("dst_port")
        event_id = self.store.insert_event(
            event.get("local_time", ""),
            event.get("logtype"),
            src or None,
            event.get("src_port"),
            dst_port,
            category,
            severity,
            event,
        )
        event["_id"] = event_id

        profile = self.profiler.update(src, category, (creds or {}).get("username"))
        self.logger(
            f"[ingest] #{event_id} {category}/{severity} src={src}:{event.get('src_port','-')} "
            f"dst_port={dst_port} label={profile.get('label','')}"
        )

        if creds:
            self.store.insert_cred(src, creds.get("username"), creds.get("password"), creds.get("service"), event_id)

        # auto-block attackers hitting failed-auth categories
        if self.ipblock and src and category in self._FAIL_CATEGORIES:
            try:
                self.ipblock.register_fail(src)
            except Exception as exc:
                self.logger(f"[ingest] ipblock error: {exc}")

        geo = self.geo.lookup(src) if src else {}
        loc = ", ".join(x for x in (geo.get("city"), geo.get("country")) if x)
        extra = f"geo: {loc or 'local'}"
        if creds:
            extra += f"\ncreds: {creds.get('username')}/{creds.get('password')} [{creds.get('service')}]"

        self.honeytokens.check_event(event, category, creds)
        self.alerts.send(event, category, severity, extra)
        self.siem.push(event)