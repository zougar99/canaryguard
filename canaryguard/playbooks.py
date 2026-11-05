"""Playbooks engine (SOAR-lite) — D12 from the roadmap.

Declarative rules evaluated in the ingest path. Rules come from config
(`playbooks.rules`) and from <home>/playbooks.json if present. Example:

    {
      "name": "lockdown on credential spray",
      "when": {"category": ["credential_spray"], "severity_gte": "high"},
      "then": [
        {"action": "block_ip", "minutes": 60},
        {"action": "notify", "text": "spray detected, blocked 1h"},
        {"action": "log"}
      ]
    }

Actions: block_ip (uses the wired IPBlocker when available), notify
(re-send through the alert channel), log. Unknown actions are skipped with
a warning, never fatal.
"""

import json
import os
import threading

from .paths import home

_SEV = ["info", "low", "medium", "high", "critical"]


def _sev_gte(sev, floor):
    try:
        return _SEV.index(sev) >= _SEV.index(floor)
    except ValueError:
        return False


class PlaybookEngine:
    def __init__(self, config, store=None, alerts=None, ipblock=None, logger=None):
        self.config = config
        self.logger = logger or print
        self.store = store
        self.alerts = alerts
        self.ipblock = ipblock
        cfg = config.section("playbooks")
        self.enabled = bool(cfg.get("enabled", False))
        self._rules = list(cfg.get("rules", []) or [])
        self._file_rules = self._load_file_rules()
        self._cooldown = {}
        self._lock = threading.Lock()

    def _load_file_rules(self):
        path = os.path.join(home(), "playbooks.json")
        try:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                return data.get("rules", []) if isinstance(data, dict) else list(data)
        except Exception as exc:
            self.logger(f"[playbooks] cannot parse {path}: {exc}")
        return []

    @property
    def rules(self):
        return self._rules + self._file_rules

    def _matches(self, rule, category, severity):
        cond = rule.get("when", {}) or {}
        cat = cond.get("category")
        if cat is not None:
            allowed = {str(c).lower() for c in (cat if isinstance(cat, list) else [cat])}
            if str(category or "").lower() not in allowed:
                return False
        floor = cond.get("severity_gte")
        if floor and not _sev_gte(severity or "info", floor):
            return False
        return True

    def _on_cooldown(self, key, minutes, now):
        last = self._cooldown.get(key)
        if last is not None and (now - last) < minutes * 60:
            return True
        self._cooldown[key] = now
        return False

    def evaluate(self, event, category, severity, extra=""):
        """Run matching rules. Returns list of executed action descriptions."""
        if not self.enabled:
            return []
        import time

        executed = []
        src_ip = (event or {}).get("src_ip") or (event or {}).get("src_host") or ""
        now = time.monotonic()
        for rule in self.rules:
            name = rule.get("name", "unnamed")
            if not self._matches(rule, category, severity):
                continue
            cooldown_min = int((rule.get("when") or {}).get("cooldown_minutes", 30))
            with self._lock:
                if self._on_cooldown(f"{name}|{src_ip}", cooldown_min, now):
                    continue
            for action in rule.get("then", []) or []:
                done = self._run_action(action, event, category, severity, src_ip, extra)
                if done:
                    executed.append(f"{name}:{action.get('action')}")
        return executed

    def _run_action(self, action, event, category, severity, src_ip, extra):
        kind = str(action.get("action", "")).lower()
        if kind == "log":
            self.logger(f"[playbooks] rule fired for {category}/{severity} src={src_ip} extra={extra}")
            return True
        if kind == "notify":
            text = action.get("text") or f"playbook action for {category} from {src_ip}"
            if self.alerts:
                try:
                    self.alerts.send(event or {}, "playbook", severity or "high", text)
                except Exception as exc:
                    self.logger(f"[playbooks] notify failed: {exc}")
            return True
        if kind == "block_ip":
            if not src_ip or src_ip in ("local", "127.0.0.1", "::1"):
                return False
            if self.ipblock:
                try:
                    minutes = int(action.get("minutes", 60))
                    self.ipblock._block(src_ip, fails=99)  # existing block pathway
                    self.logger(f"[playbooks] blocked {src_ip} ({minutes} min requested)")
                    return True
                except Exception as exc:
                    self.logger(f"[playbooks] block_ip failed: {exc}")
                    return False
            self.logger(f"[playbooks] block_ip requested for {src_ip} but ipblocker is unavailable")
            return False
        self.logger(f"[playbooks] unknown action: {kind}")
        return False
