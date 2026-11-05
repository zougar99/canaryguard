"""AI Triage Brief — a small, local, advisory security analyst.

Reads the last 24h/7d of events straight from SQLite, feeds a *compact*
context to a local model (Qwen2.5-0.5B GGUF via llama-server) and returns a
plain-text brief: risk level, key observations, suggested next steps.

Safety rules baked in:
  * advisory only — nothing here ever changes state, blocks an IP, stops or
    restarts anything. Suggestions still require a human in the loop.
  * all context is generated locally; no data ever leaves the machine.
  * if the model is missing, slow or fails, a deterministic rules-based
    brief is produced instead (the module never hard-fails).
"""

import json
import os
import time
from datetime import datetime

import requests

from .config import get_store
from ._winproc import detach

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_MODEL = r"C:\Users\werlist99\Desktop\Qwen2.5-0.5B-Instruct.Q4_K_M.gguf"
DEFAULT_SERVER_EXE = os.path.join(BASE, "tools", "llama-bin", "llama-server.exe")
DEFAULT_PORT = 11435

SYSTEM_PROMPT = (
    "You are a security triage assistant for a self-hosted honeypot on one "
    "Windows PC. You are given JSON statistics. Write a SHORT brief "
    "(max 180 words, plain text, no markdown):\n"
    "1) overall risk: calm / elevated / serious\n"
    "2) the two or three most important observations (name the exact IPs, "
    "ports, categories and times that appear in the data)\n"
    "3) concrete next steps for the operator.\n"
    "Rules: never invent addresses, ports, trends, teams or increases that "
    "are not in the data; repeat the exact counts from the JSON. "
    "If the data is sparse, say so plainly. Do not recommend unsupervised "
    "automated actions. Plain text only."
)


class AITriage:
    def __init__(self, config, alerts=None, logger=None):
        self.config = config
        self.alerts = alerts
        self.logger = logger or print
        cfg = config.section("ai_brief")
        self.enabled = bool(cfg.get("enabled", True))
        self.provider = str(cfg.get("provider", "auto")).lower()   # auto|server|rules
        self.model_path = str(cfg.get("model_path", DEFAULT_MODEL))
        self.server_exe = str(cfg.get("llama_server", DEFAULT_SERVER_EXE))
        self.server_url = str(cfg.get("server_url", f"http://127.0.0.1:{DEFAULT_PORT}")).rstrip("/")
        self.temperature = float(cfg.get("temperature", 0.2))
        self.num_predict = int(cfg.get("num_predict", 320))
        self.timeout = float(cfg.get("timeout_seconds", 75))
        self.store = get_store(config)
        self._lock = __import__("threading").Lock()
        self._cache = {"ts": 0.0, "text": "", "provider": "", "generated_at": ""}

    # ---------------- context gathering ----------------

    def gather(self):
        hours = 24
        cats = dict(self.store.counts_by_category(hours))
        sev = dict(self.store.counts_by_severity(hours))
        cats_7d = dict(self.store.counts_by_category(hours * 7))
        sev_7d = dict(self.store.counts_by_severity(hours * 7))
        top_ips = self.store.top_ips(5, hours)
        repeat = self.store.repeat_ips(3, 10)
        hist = self.store.hourly_histogram(90)
        fails = self.store.failed_logins(hours)
        uniq7 = self.store.unique_ips(7)
        peak_hour, peak_val = max(enumerate(hist), key=lambda kv: kv[1]) if hist and max(hist) > 0 else (0, 0)
        total_24 = sum(cats.values())
        total_7d = sum(cats_7d.values())
        ctx = {
            "window": "last 24h",
            "events_24h": total_24,
            "events_7d": total_7d,
            "severities_24h": sev,
            "severities_7d": sev_7d,
            "top_categories_24h": sorted(cats.items(), key=lambda kv: -kv[1])[:6],
            "top_categories_7d": sorted(cats_7d.items(), key=lambda kv: -kv[1])[:6],
            "top_source_ips_24h": [{"ip": row.get("src_ip"), "events": row.get("n")}
                                    for row in top_ips],
            "repeat_offenders": [{"ip": r["src_ip"], "hits": r["n"],
                                    "first_seen": r["first_seen"],
                                    "last_seen": r["last_seen"]} for r in repeat],
            "unique_attackers_7d": uniq7,
            "failed_logins_24h": fails,
            "attack_clock_peak": {"hour": int(peak_hour), "events": int(peak_val)},
        }
        return ctx

    def build_context(self, ctx):
        return json.dumps(ctx, ensure_ascii=False, separators=(",", ":"))

    # ---------------- provider: local GGUF via llama-server ----------------

    def _server_up(self):
        try:
            r = requests.get(f"{self.server_url}/health", timeout=2)
            return r.status_code in (200, 503)   # 503 = loading, still up
        except Exception:
            return False

    def _ensure_server(self):
        if self._server_up():
            return True
        if not (os.path.exists(self.server_exe) and os.path.exists(self.model_path)):
            self.logger("[ai] llama-server or model missing")
            return False
        port = int(self.server_url.rsplit(":", 1)[-1].split("/")[0])
        try:
            detach([self.server_exe, "-m", self.model_path, "-c", "1024",
                    "-ngl", "0", "--port", str(port), "--no-webui"])
            self.logger(f"[ai] starting llama-server on port {port}")
        except Exception as exc:
            self.logger(f"[ai] cannot start llama-server: {exc}")
            return False
        for _ in range(120):
            time.sleep(0.5)
            if self._server_up():
                return True
        self.logger("[ai] llama-server did not come up")
        return False

    def _ask_model(self, ctx_json):
        r = requests.post(
            f"{self.server_url}/v1/chat/completions",
            json={
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": "JSON stats:\n" + ctx_json},
                ],
                "temperature": self.temperature,
                "max_tokens": self.num_predict,
                "seed": 42,
            },
            timeout=self.timeout,
        )
        r.raise_for_status()
        out = r.json()["choices"][0]["message"]["content"].strip()
        return out

    # ---------------- provider: deterministic rules fallback ----------------

    @staticmethod
    def _fmt_cats(pairs):
        return ", ".join(f"{k} {v}" for k, v in pairs) or "none"

    def rules_brief(self, ctx):
        sev = ctx.get("severities_24h") or {}
        crit = int(sev.get("critical", 0))
        high = int(sev.get("high", 0))
        total = ctx.get("events_24h", 0)
        total7 = ctx.get("events_7d", 0)
        uniq = ctx.get("unique_attackers_7d", 0)
        rep = ctx.get("repeat_offenders") or []
        ips = ctx.get("top_source_ips_24h") or []
        peak = ctx.get("attack_clock_peak") or {}
        if crit == 0 and high == 0:
            risk = "calm"
        elif high > 0 and crit == 0:
            risk = "elevated"
        else:
            risk = "serious"
        lines = [
            f"Risk: {risk}.",
            f"Last 24h: {total} events; 7d: {total7}; unique attackers (7d): {uniq}.",
            f"Severity (24h): critical {crit}, high {high}, "
            f"medium {int(sev.get('medium', 0))}, low {int(sev.get('low', 0))}.",
        ]
        if ctx.get("top_categories_24h"):
            lines.append("Most hit: " + self._fmt_cats(ctx["top_categories_24h"]) + ".")
        if ips:
            lines.append("Top sources (24h): " +
                         ", ".join(f"{i['ip']} ({i['events']})" for i in ips) + ".")
        if rep:
            worst = rep[0]
            lines.append(f"Repeat offender: {worst['ip']} — {worst['hits']} hits "
                         f"(first {str(worst['first_seen'])[:10]}, "
                         f"last {str(worst['last_seen'])[:10]}).")
        if peak.get("events", 0) > 0:
            lines.append(f"Attack clock peak: hour {peak['hour']:02d}:00 "
                         f"({peak['events']} events in 90 days).")
        if ctx.get("failed_logins_24h"):
            lines.append(f"Failed logins (24h): {ctx['failed_logins_24h']}.")
        if risk == "calm":
            lines.append("Nothing demands immediate action. Keep current posture; "
                         "review the Insights tab if events climb.")
        else:
            lines.append("Next steps: 1) inspect the repeat offenders above and "
                         "block any anonymous source with ≥3 hits; 2) verify monitors are "
                         "all running; 3) check failed logins; 4) consider tightening "
                         "min_severity or quiet hours.")
        return "\n".join(lines)

    # ---------------- public API ----------------

    def brief(self, fresh=False):
        if not self.enabled:
            return {"enabled": False, "brief": "", "provider": "off",
                    "generated_at": None, "cached": False}
        with self._lock:
            age = time.time() - self._cache["ts"]
            if not fresh and self._cache["text"] and age < 600:
                return {"enabled": True, "cached": True,
                        "brief": self._cache["text"],
                        "provider": self._cache["provider"],
                        "generated_at": self._cache["generated_at"]}
            ctx = self.gather()
            ctx_json = self.build_context(ctx)
            text_rules = self.rules_brief(ctx)
            text, used = text_rules, "rules"
            provider = self.provider
            if provider in ("auto", "server"):
                if self._ensure_server():
                    try:
                        llm = self._ask_model(ctx_json)
                        text = text_rules + "\n\n— model notes (local Qwen2.5-0.5B) —\n" + llm
                        used = f"rules + qwen2.5-0.5b-q4_k_m (local) · {self.server_url}"
                    except Exception as exc:
                        self.logger(f"[ai] model failed, keeping rules brief only: {exc}")
                elif provider == "server":
                    text = ("Local model not available and provider=server. "
                            "Set ai_brief.provider to 'auto' or 'rules'.")
                    used = "unavailable"
            stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self._cache.update({"ts": time.time(), "text": text,
                                "provider": used, "generated_at": stamp})
            return {"enabled": True, "cached": False, "brief": text,
                    "provider": used, "generated_at": stamp}
