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
from .paths import state_file
from .commonpass import is_common_password
from .changepoint import RateChangeDetector
from .playbooks import PlaybookEngine
from .rarity import RarityModel, bump_once
from .spray import SprayDetector

STATE_FILE = state_file("ingest_state.json")


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
        acfg = config.section("analytics")
        self.analytics_enabled = bool(acfg.get("enabled", True))
        self.rarity = RarityModel(config, store=self.store) if acfg.get("rarity_boost", True) else None
        self._rarity_rarity = float(acfg.get("rarity_min", 0.80))
        self._rarity_max_count = int(acfg.get("rarity_max_count", 2))
        self.changepoint = RateChangeDetector() if acfg.get("changepoint", True) else None
        self._cp_cooldown = float(acfg.get("changepoint_cooldown_seconds", 300))
        self._cp_last_alert = 0.0
        self.spray_detector = SprayDetector(
            window_seconds=int(acfg.get("spray_window_seconds", 600)),
            min_ips_same_password=int(acfg.get("spray_min_ips", 5)),
            min_users_same_ip=int(acfg.get("spray_min_users", 10)),
        ) if acfg.get("spray_detection", True) else None
        self.playbooks = PlaybookEngine(config, store=self.store, alerts=self.alerts, ipblock=ipblock)
        self._offset = None
        self._stop = threading.Event()
        self._load_state()

    _FAIL_CATEGORIES = {"brute_force", "web_login_attack", "database_attack", "auth:fail", "shell_command"}

    def _load_state(self):
        self._ino = None
        try:
            if os.path.exists(STATE_FILE):
                with open(STATE_FILE, "r", encoding="utf-8") as fh:
                    state = json.load(fh)
                if state.get("log_file") == self.log_file:
                    self._offset = state.get("offset")
                    self._ino = state.get("ino")
        except Exception:
            self._offset = None
            self._ino = None

    def _save_state(self):
        try:
            with open(STATE_FILE, "w", encoding="utf-8") as fh:
                json.dump({"log_file": self.log_file, "offset": self._offset, "ino": self._ino}, fh)
        except Exception:
            pass

    def start(self):
        self.siem.start()
        threading.Thread(target=self._run, daemon=True).start()

    def stop(self):
        self._stop.set()
        self.siem.stop()

    def _maybe_reset_for_rotation(self, path):
        """Detect log rotation/truncation; reset offset when the file changed identity."""
        try:
            st = os.stat(path)
        except OSError:
            return
        if self._offset is not None:
            if st.st_size < self._offset:
                self.logger(f"[ingest] log rotated (size {st.st_size} < offset {self._offset}) — starting from 0")
                self._offset = None
                self._ino = None
                return
            if self._ino is not None and st.st_ino and st.st_ino != self._ino:
                self.logger("[ingest] log rotated (inode changed) — starting from 0")
                self._offset = None
                self._ino = None
        self._ino = st.st_ino

    def _tail(self, handle):
        """Yield new lines appended after the current offset."""
        self._maybe_reset_for_rotation(self.log_file)
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

        if self.analytics_enabled and self.rarity:
            try:
                rarity, seen = self.rarity.score(service, category)
                if self.rarity.should_boost(rarity, seen, min_total_rarity=self._rarity_rarity,
                                            max_count=self._rarity_max_count):
                    extra += f"\nrare pattern (rarity={rarity:.2f}, seen={seen}) — severity bumped"
                    severity = bump_once(severity)
            except Exception as exc:
                self.logger(f"[ingest] rarity error: {exc}")

        if creds and self.analytics_enabled:
            password = creds.get("password") or ""
            if is_common_password(password):
                extra += "\npassword: matches common/breached-password corpus"
            if self.spray_detector:
                try:
                    findings = self.spray_detector.observe(src, creds.get("username"), password, service)
                    for finding in findings or []:
                        if finding["kind"] == "password_spray":
                            msg = (f"credential spray: one password tried from {finding['distinct_ips']} distinct IPs "
                                   f"(e.g. {', '.join(finding['ips'][:5])})")
                        else:
                            msg = (f"username fan-out: {src} tried {finding['distinct_usernames']} distinct usernames "
                                   f"in the window")
                        extra += f"\n{msg}"
                        self.alerts.send(event, "credential_spray", "high", msg)
                except Exception as exc:
                    self.logger(f"[ingest] spray detection error: {exc}")

        if self.changepoint:
            try:
                import time as _time
                self.changepoint.observe()
                shift = self.changepoint.check()
                if shift and (_time.monotonic() - self._cp_last_alert) > self._cp_cooldown:
                    self._cp_last_alert = _time.monotonic()
                    self.alerts.send(event, "anomaly:changepoint", "high",
                                     f"event-rate change point detected ({shift}) — slow-and-low scan or attack ramp")
            except Exception as exc:
                self.logger(f"[ingest] changepoint error: {exc}")

        self.honeytokens.check_event(event, category, creds)
        self.alerts.send(event, category, severity, extra)
        self.siem.push(event)
        try:
            executed = self.playbooks.evaluate(event, category, severity, extra)
            if executed:
                self.logger(f"[ingest] playbooks: {', '.join(executed)}")
        except Exception as exc:
            self.logger(f"[ingest] playbooks error: {exc}")
