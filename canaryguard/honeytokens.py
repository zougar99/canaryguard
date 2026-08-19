import json
import os
import threading

from .alerts import AlertManager
from .classifier import classify
from .config import get_store
from .geolocate import GeoLocator

HONEYTOKEN_FILE = "C:\\Users\\werlist99\\canaryguard\\canaryguard\\honeytokens_state.json"


class HoneytokenManager:
    """Detects when honeytokens (URLs / credentials) are tripped."""

    def __init__(self, config, alerts: AlertManager, geo: GeoLocator, logger=None):
        self.config = config
        self.store = get_store(config)
        self.alerts = alerts
        self.geo = geo
        self.logger = logger or print
        cfg = config.section("honeytokens")
        self.url_tokens = cfg.get("url_tokens", [])
        self.cred_tokens = cfg.get("credential_tokens", [])
        self._lock = threading.Lock()
        self._tripped = set()
        self._load_state()

    def _load_state(self):
        try:
            if os.path.exists(HONEYTOKEN_FILE):
                with open(HONEYTOKEN_FILE, "r", encoding="utf-8") as fh:
                    self._tripped = set(json.load(fh))
        except Exception:
            self._tripped = set()

    def _save_state(self):
        try:
            with open(HONEYTOKEN_FILE, "w", encoding="utf-8") as fh:
                json.dump(list(self._tripped), fh)
        except Exception:
            pass

    def match_creds(self, username, password, service):
        if username is None:
            return None
        for tok in self.cred_tokens:
            if username == tok.get("username") and password == tok.get("password"):
                return tok
        for d in self.store.decoy_creds():
            if username == d.get("username") and password == d.get("password"):
                return {
                    "id": d.get("token_id"),
                    "username": username,
                    "password": password,
                    "label": f"decoy file creds: {os.path.basename(d.get('path') or '?')}",
                    "severity": "critical",
                }
        return None

    def check_event(self, event, category, creds):
        """Return True if the event tripped a honeytoken."""
        logdata = event.get("logdata", {})
        path = str(logdata.get("PATH", "") or "")
        src = event.get("src_host") or event.get("src_ip") or "?"
        geo = self.geo.lookup(src) if self.geo else {}
        loc = ", ".join(x for x in (geo.get("city"), geo.get("country")) if x)

        tok = None
        kind = None

        if path:
            for t in self.url_tokens:
                if path == t.get("path"):
                    tok, kind = t, "URL honeytoken"
                    break

        if tok is None and creds:
            t = self.match_creds(creds.get("username"), creds.get("password"), creds.get("service"))
            if t:
                tok, kind = t, "Credential honeytoken"

        if tok is None:
            return False

        key = tok.get("id") or f"{kind}:{tok.get('username')}:{tok.get('password')}"
        with self._lock:
            if key in self._tripped:
                return True
            self._tripped.add(key)
            self._save_state()

        sev = tok.get("severity", "critical")
        self.store.insert_token_trip(
            key,
            "credential" if creds else "url",
            f"{kind}: {tok.get('label')}",
            f"src={src} ({loc}) service={creds.get('service') if creds else ''}",
            {"src": src, "loc": loc, "path": path, "creds": creds, "event": event.get("local_time")},
        )
        msg = (
            f"TOKEN TRIPPED: {kind} '{tok.get('label')}'\n"
            f"src: {src} ({loc})\n"
            f"path/service: {path or creds.get('service')}\n"
            f"creds: {creds.get('username')}/{creds.get('password') if creds else '-'}\n"
            f"time: {event.get('local_time', '')}"
        )
        self.alerts.send(event, f"honeytoken:{tok.get('id')}", sev, msg)
        self.logger(f"[honeytokens] TRIPPED {kind} {tok.get('id')} from {src}")
        return True