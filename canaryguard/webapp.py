import functools
import json
import os
import secrets as pysecrets
import threading
import time
from datetime import datetime

from flask import (Flask, Response, jsonify, redirect, render_template,
                   request, session, stream_with_context, url_for)

from .config import get_store

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

AUTH_EXEMPT_PREFIXES = ("/login", "/t/", "/static/")


class DashboardServer:
    def __init__(self, config, logger=None, decoys=None, cleanup=None, sessions=None, keystrokes=None, secrets=None, embeds=None, alerts=None, monitors=None, ipblock=None, runtime=None):
        self.config = config
        self.logger = logger or print
        self.store = get_store(config)
        self.decoys = decoys
        self.cleanup = cleanup
        self.sessions = sessions
        self.keystrokes = keystrokes
        self.secrets = secrets
        self.embeds = embeds
        self.alerts = alerts
        self.monitors = monitors or {}
        self.ipblock = ipblock
        self.runtime = runtime
        self.app = Flask(__name__, template_folder=os.path.join(BASE_DIR, "templates"), static_folder=os.path.join(BASE_DIR, "static"))
        self.app.secret_key = config.get("dashboard", "secret_key", default=pysecrets.token_hex(32))
        self._username = config.get("dashboard", "username", default="admin")
        self._password = config.get("dashboard", "password", default=None)
        self._blocked_cache = (0.0, [])
        self._blocked_lock = threading.Lock()
        self._register_routes()

    def _auth_enabled(self):
        return bool(self._password)

    def _authorized(self):
        return session.get("cg_authed") is True

    def _local_ip_ok(self, ip):
        """Loopback, plus any subnet listed in dashboard.trusted_networks.

        Use trusted_networks for a VPN tunnel (e.g. 10.8.0.0/24 for
        WireGuard, 100.64.0.0/10 for Tailscale) so remote access works
        without putting a password on the dashboard.
        """
        if ip in ("127.0.0.1", "::1", "localhost"):
            return True
        nets = self.config.get("dashboard", "trusted_networks", default=None) or []
        if not nets:
            return False
        try:
            import ipaddress

            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for net in nets:
            try:
                if addr in ipaddress.ip_network(str(net), strict=False):
                    return True
            except ValueError:
                continue
        return False

    def _before_request(self):
        if not self._auth_enabled():
            # No password configured: allow this PC only, unless explicitly
            # opted-in via dashboard.noauth_allow_remote. Keeps the LAN /
            # internet from reaching an unauthenticated dashboard.
            if not self.config.get("dashboard", "noauth_allow_remote", default=False):
                ip = request.remote_addr or ""
                if not self._local_ip_ok(ip):
                    if request.path.startswith("/api/"):
                        return jsonify({"error": "local access only (no dashboard password set)"}), 403
                    return ("CanaryGuard dashboard is local-only (no password set). "
                            "Add your VPN subnet to dashboard.trusted_networks to allow it."), 403
            return None
        path = request.path
        if path.startswith(AUTH_EXEMPT_PREFIXES):
            return None
        if self._authorized():
            return None
        if request.path.startswith("/api/"):
            return jsonify({"error": "unauthorized"}), 401
        return redirect(url_for("login"))

    def _alert_login_fail(self, attempted_user):
        if not self.alerts:
            return
        ip = request.headers.get("X-Forwarded-For", request.remote_addr or "?")
        event = {"src_host": str(ip), "src_port": "-", "dst_port": 8080,
                 "local_time": "", "ts": ""}
        try:
            self.alerts.send(
                event, "auth:fail", "high",
                f"FAILED LOGIN on dashboard\n"
                f"attempted user: {attempted_user or '(empty)'}\n"
                f"from IP: {ip}",
            )
        except Exception as exc:
            self.logger(f"[webapp] login-fail alert error: {exc}")
        # brute-force panic lockout
        try:
            from .panic import PanicManager
            pm = getattr(self.alerts, "_panic", None)
            if pm:
                pm.register_login_fail()
        except Exception:
            pass

    def _night_state(self):
        """Quiet-hours window used by the alert engine (UI banner)."""
        cfg = self.config.section("alerts")
        enabled = bool(cfg.get("night_escalation", False))
        start = str(cfg.get("night_start", "23:00"))
        end = str(cfg.get("night_end", "07:00"))
        floor = str(cfg.get("night_floor", "high"))
        now = datetime.now().strftime("%H:%M")
        active = False
        if enabled:
            try:
                if start <= end:
                    active = start <= now < end
                else:
                    active = now >= start or now < end
            except Exception:
                active = False
        return {"enabled": enabled, "active": active, "start": start,
                "end": end, "floor": floor, "now": now}

    def _muted_categories(self):
        return sorted(str(m) for m in getattr(self.alerts, "muted", set())) if self.alerts else []

    def _blocked_ips(self, ttl=20):
        """Windows firewall rules created by the IP blocker, cached briefly.

        ``netsh`` takes roughly a second, so never run it on every poll.
        """
        with self._blocked_lock:
            stamp, cached = self._blocked_cache
            if time.time() - stamp < ttl:
                return cached
        ips = []
        try:
            from ._winproc import run as _proc_run

            out = _proc_run(
                ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
                capture_output=True, text=True, timeout=15,
            ).stdout
            for chunk in out.split("Rule Name:"):
                lines = [ln.strip() for ln in chunk.splitlines() if ln.strip()]
                if not lines or not lines[0].startswith("CanaryBlock"):
                    continue
                for line in lines:
                    if line.upper().startswith("REMOTEIP"):
                        for part in line.split(":", 1)[1].replace("/", " ").split():
                            ip = part.split("/")[0]
                            if "." in ip:
                                ips.append(ip)
        except Exception:
            ips = []
        ips = sorted(set(ips))
        with self._blocked_lock:
            self._blocked_cache = (time.time(), ips)
        return ips

    def _overview_payload(self, events=15):
        """One-shot payload shared by /api/overview and the SSE stream."""
        from . import control as ctl

        store = self.store
        monitors = {}
        running = 0
        for name, mon in self.monitors.items():
            status = self._mon_status(mon)
            if status == "running":
                running += 1
            monitors[name] = {"status": status, "class": type(mon).__name__}

        state = ctl.status()
        if self.runtime is not None:
            state["mode"] = self.runtime.mode
        state["monitors_running"] = running
        state["monitors_total"] = len(monitors)

        return {
            "server_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "stats": {
                "total": store.total_events(),
                "creds": store.total_creds(),
                "categories": store.counts_by_category(),
                "severities": store.counts_by_severity(),
                "timeline": store.timeline(),
                "top_ips": store.top_ips(),
                "geo": store.geo_points(),
                "first_seen": store.first_ts(),
            },
            "counts": {
                "events": store.total_events(),
                "creds": store.total_creds(),
                "sessions": store.total_sessions(),
                "keys": store.total_keystrokes(),
                "files": store.total_file_events(),
                "secrets": store.total_secret_hits(),
                "procs": store.total_process_events(),
                "usb": store.total_usb_events(),
                "clip": store.total_clipboard_events(),
                "net": store.total_net_events(),
                "cam": store.total_cam_events(),
            },
            "monitors": monitors,
            "control": state,
            "events": store.recent_events(events),
            "night": self._night_state(),
            "muted": self._muted_categories(),
            "blocked": self._blocked_ips(),
        }

    def _register_routes(self):
        app = self.app
        app.before_request(self._before_request)

        @app.route("/login", methods=["GET", "POST"])
        def login():
            if not self._auth_enabled():
                return redirect(url_for("index"))
            if request.method == "POST":
                user = (request.form.get("username") or "").strip()
                pwd = request.form.get("password") or ""
                if user == self._username and pwd == self._password:
                    session["cg_authed"] = True
                    return redirect(url_for("index"))
                self._alert_login_fail(user)
                return render_template("login.html", error="Invalid credentials"), 401
            return render_template("login.html", error=None)

        @app.route("/api/test_alert", methods=["POST"])
        def api_test_alert():
            if not self.alerts:
                return jsonify({"error": "alerts not available"}), 503
            sent = self.alerts.send_raw(
                "\U0001f9fe TEST NOTIFICATION\n"
                "CanaryGuard Telegram channel khdam 100%.\n"
                f"time: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )
            return jsonify({"ok": True, "sent_via": sent})

        # ---- notification channel settings (Telegram / Discord / email) ----

        _MASK = "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022"

        def _mask(value, keep=4):
            s = str(value or "")
            if not s:
                return ""
            return _MASK + s[-keep:] if len(s) > keep else _MASK

        def _keep_secret(value, current):
            """Masked placeholder sent back = keep the stored secret."""
            if value is None:
                return current
            s = str(value).strip()
            if s == _MASK or s.startswith(_MASK):
                return current
            return s

        def _read_raw_config():
            try:
                with open(self.config.path, "r", encoding="utf-8") as fh:
                    return json.load(fh)
            except Exception:
                return dict(self.config.data or {})

        def _notify_state():
            raw = _read_raw_config()
            alerts = raw.get("alerts") if isinstance(raw.get("alerts"), dict) else {}
            tg = alerts.get("telegram") or {}
            dc = alerts.get("discord") or {}
            em = alerts.get("email") or {}
            return {
                "telegram": {
                    "enabled": bool(tg.get("enabled")),
                    "chat_id": str(tg.get("chat_id") or ""),
                    "bot_token": _mask(tg.get("bot_token")),
                    "configured": bool(tg.get("bot_token") and tg.get("chat_id")),
                },
                "discord": {
                    "enabled": bool(dc.get("enabled")),
                    "webhook_url": _mask(dc.get("webhook_url"), keep=14),
                    "configured": bool(str(dc.get("webhook_url") or "").strip()),
                },
                "email": {
                    "enabled": bool(em.get("enabled")),
                    "smtp_host": str(em.get("smtp_host") or ""),
                    "smtp_port": int(em.get("smtp_port") or 587),
                    "username": str(em.get("username") or ""),
                    "from_addr": str(em.get("from_addr") or ""),
                    "to_addr": str(em.get("to_addr") or ""),
                    "password": _MASK if em.get("password") else "",
                    "configured": bool(em.get("smtp_host") and em.get("from_addr") and em.get("to_addr")),
                },
            }

        @app.route("/api/notify")
        def api_notify_get():
            return jsonify(_notify_state())

        @app.route("/api/notify", methods=["POST"])
        def api_notify_save():
            import re

            body = request.get_json(silent=True) or {}
            channel = (body.get("channel") or "").lower()
            if channel not in ("telegram", "discord", "email"):
                return jsonify({"error": "unknown channel"}), 400
            raw = _read_raw_config()
            if not isinstance(raw, dict):
                return jsonify({"error": "cannot read config.json"}), 500
            alerts = raw.setdefault("alerts", {})
            if not isinstance(alerts, dict):
                return jsonify({"error": "alerts section is not an object"}), 500
            sec = dict(alerts.get(channel) or {})
            enabled = bool(body.get("enabled"))

            if channel == "telegram":
                sec["bot_token"] = _keep_secret(body.get("bot_token"), sec.get("bot_token", ""))
                sec["chat_id"] = str(body.get("chat_id", sec.get("chat_id", "")) or "").strip()
                token = sec["bot_token"]
                if enabled and not re.match(r"^\d{4,}:[A-Za-z0-9_-]{20,}$", token or ""):
                    return jsonify({"error": "bot_token looks invalid — it must look like 123456789:AAH..."}), 400
                if enabled and not re.match(r"^-?\d+$", sec["chat_id"] or ""):
                    return jsonify({"error": "chat_id must be a number (groups/supergroups are negative)"}), 400
            elif channel == "discord":
                sec["webhook_url"] = _keep_secret(body.get("webhook_url"), sec.get("webhook_url", ""))
                url = sec["webhook_url"] or ""
                if enabled and not (url.startswith("https://discord.com/api/webhooks/")
                                    or url.startswith("https://discordapp.com/api/webhooks/")):
                    return jsonify({"error": "webhook URL must start with https://discord.com/api/webhooks/"}), 400
            elif channel == "email":
                sec["smtp_host"] = str(body.get("smtp_host", sec.get("smtp_host", "")) or "").strip()
                try:
                    port = int(body.get("smtp_port", sec.get("smtp_port", 587)))
                except (TypeError, ValueError):
                    return jsonify({"error": "smtp_port must be a number (e.g. 587)"}), 400
                if not 1 <= port <= 65535:
                    return jsonify({"error": "smtp_port out of range"}), 400
                sec["smtp_port"] = port
                sec["username"] = str(body.get("username", sec.get("username", "")) or "").strip()
                sec["password"] = _keep_secret(body.get("password"), sec.get("password", ""))
                sec["from_addr"] = str(body.get("from_addr", sec.get("from_addr", "")) or "").strip()
                sec["to_addr"] = str(body.get("to_addr", sec.get("to_addr", "")) or "").strip()
                if enabled:
                    if not sec["smtp_host"]:
                        return jsonify({"error": "smtp_host is required"}), 400
                    if not (sec["from_addr"] and "@" in sec["from_addr"]
                            and sec["to_addr"] and "@" in sec["to_addr"]):
                        return jsonify({"error": "from_addr and to_addr must be valid addresses"}), 400

            sec["enabled"] = enabled
            alerts[channel] = sec
            try:
                with open(self.config.path, "w", encoding="utf-8") as fh:
                    json.dump(raw, fh, indent=4, ensure_ascii=False)
                self.config.data = raw
            except Exception as exc:
                return jsonify({"error": f"cannot write config.json: {exc}"}), 500
            if self.alerts is not None:
                setattr(self.alerts, channel, dict(sec))
            return jsonify({"ok": True, "channel": channel, "state": _notify_state()[channel]})

        @app.route("/api/notify/test", methods=["POST"])
        def api_notify_test():
            if not self.alerts:
                return jsonify({"error": "alerts not available"}), 503
            body = request.get_json(silent=True) or {}
            ch = (body.get("channel") or "").lower()
            if ch not in ("telegram", "discord", "email"):
                return jsonify({"error": "unknown channel"}), 400
            cfg = getattr(self.alerts, ch) or {}
            stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            subject = "CanaryGuard TEST alert"
            msg = f"CanaryGuard test notification\nchannel: {ch}\ntime: {stamp}"
            try:
                if ch == "telegram":
                    if not (cfg.get("enabled") and cfg.get("bot_token") and cfg.get("chat_id")):
                        return jsonify({"error": "Telegram is not enabled/configured yet"}), 400
                    self.alerts._send_telegram(subject, msg)
                elif ch == "discord":
                    if not (cfg.get("enabled") and cfg.get("webhook_url")):
                        return jsonify({"error": "Discord webhook is not enabled/configured yet"}), 400
                    self.alerts._send_discord(subject, msg)
                else:
                    if not (cfg.get("enabled") and cfg.get("smtp_host") and cfg.get("to_addr")):
                        return jsonify({"error": "email is not enabled/configured yet"}), 400
                    self.alerts._send_email(subject, msg)
            except Exception as exc:
                return jsonify({"error": f"{ch} delivery failed: {exc}"}), 502
            return jsonify({"ok": True, "channel": ch, "sent_at": stamp})

        @app.route("/logout")
        def logout():
            session.pop("cg_authed", None)
            return redirect(url_for("login"))

        @app.route("/")
        def index():
            return render_template("index.html")

        @app.route("/console")
        def console():
            """Full-screen NOC view fed by /api/stream (server-sent events)."""
            return render_template("console.html")

        @app.route("/api/overview")
        def api_overview():
            return jsonify(self._overview_payload())

        @app.route("/api/stream")
        def api_stream():
            """Server-sent events: one JSON tick every few seconds."""
            try:
                interval = float(request.args.get("interval", 3))
            except ValueError:
                interval = 3.0
            interval = min(15.0, max(1.0, interval))

            def generate():
                while True:
                    try:
                        payload = self._overview_payload()
                    except Exception as exc:  # keep the stream alive
                        payload = {"error": str(exc),
                                   "server_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
                    yield "data: " + json.dumps(payload, ensure_ascii=False) + "\n\n"
                    time.sleep(interval)

            headers = {
                "Cache-Control": "no-cache, no-transform",
                "X-Accel-Buffering": "no",
                "Connection": "keep-alive",
            }
            return Response(stream_with_context(generate()),
                            mimetype="text/event-stream", headers=headers)

        @app.route("/api/night")
        def api_night():
            return jsonify(self._night_state())

        @app.route("/api/insights")
        def api_insights():
            """Who keeps coming back — repeat offenders + attack clock."""
            store = self.store
            repeat = store.repeat_ips(3, 20)
            blocked = set(self._blocked_ips(ttl=10))
            payload = []
            for row in repeat:
                ip = row["src_ip"]
                try:
                    m = store.ip_meta(ip) or {}
                except Exception:
                    m = {}
                payload.append({
                    "ip": ip,
                    "hits": row["n"],
                    "first_seen": row["first_seen"],
                    "last_seen": row["last_seen"],
                    "country": m.get("country") or "",
                    "city": m.get("city") or "",
                    "org": m.get("org") or "",
                    "blocked": ip in blocked,
                })
            try:
                events_7d = int(sum(n for _, n in store.timeline(7 * 24)))
            except Exception:
                events_7d = 0
            return jsonify({
                "repeat": payload,
                "hours": store.hourly_histogram(90),
                "unique_7d": store.unique_ips(7),
                "unique_30d": store.unique_ips(30),
                "blocked": len(blocked),
                "events_7d": events_7d,
            })

        @app.route("/api/stats")
        def api_stats():
            return jsonify({
                "total": self.store.total_events(),
                "creds": self.store.total_creds(),
                "categories": self.store.counts_by_category(),
                "severities": self.store.counts_by_severity(),
                "timeline": self.store.timeline(),
                "top_ips": self.store.top_ips(),
                "geo": self.store.geo_points(),
                "first_seen": self.store.first_ts(),
            })

        @app.route("/api/events")
        def api_events():
            limit = min(int(self.config.get("dashboard", "event_limit", default=50)), 500)
            return jsonify(self.store.recent_events(limit))

        @app.route("/api/creds")
        def api_creds():
            return jsonify(self.store.creds_captured(100))

        @app.route("/api/tokens")
        def api_tokens():
            return jsonify({
                "decoys": self.store.decoys(),
                "trips": self.store.token_trips(100),
            })

        @app.route("/t/<path:token_id>")
        def beacon(token_id):
            src = request.headers.get("X-Forwarded-For", request.remote_addr or "")
            ua = request.headers.get("User-Agent", "")
            if self.decoys:
                self.decoys.trip(
                    token_id,
                    "beacon",
                    f"beacon URL hit",
                    src_info=f"ip={src} ua={ua}",
                    raw={"ip": src, "ua": ua, "path": request.full_path},
                )
            return ("404 Not Found", 404)

        @app.route("/api/ip/<path:src_ip>")
        def api_ip(src_ip):
            return jsonify({"ip": src_ip, "meta": self.store.ip_meta(src_ip), "events": self.store.ip_history(src_ip)})

        @app.route("/api/sessions")
        def api_sessions():
            return jsonify({
                "total": self.store.total_sessions(),
                "failed": self.store.failed_logins(),
                "sessions": self.store.recent_sessions(100),
            })

        @app.route("/api/keys")
        def api_keys():
            return jsonify({
                "total": self.store.total_keystrokes(),
                "entries": self.store.recent_keystrokes(100),
            })

        @app.route("/api/files")
        def api_files():
            return jsonify({
                "total": self.store.total_file_events(),
                "entries": self.store.recent_file_events(100),
            })

        @app.route("/api/secrets")
        def api_secrets():
            return jsonify({
                "total": self.store.total_secret_hits(),
                "entries": self.store.recent_secret_hits(100),
            })

        @app.route("/api/processes")
        def api_processes():
            return jsonify({
                "total": self.store.total_process_events(),
                "entries": self.store.recent_process_events(100),
            })

        @app.route("/api/usb")
        def api_usb():
            return jsonify({
                "total": self.store.total_usb_events(),
                "entries": self.store.recent_usb_events(100),
            })

        @app.route("/api/clipboard")
        def api_clipboard():
            return jsonify({
                "total": self.store.total_clipboard_events(),
                "entries": self.store.recent_clipboard_events(100),
            })

        @app.route("/api/net")
        def api_net():
            return jsonify({
                "total": self.store.total_net_events(),
                "entries": self.store.recent_net_events(100),
            })

        @app.route("/api/embed/verify")
        def api_embed_verify():
            if not self.embeds:
                return jsonify({"error": "embedded tokens disabled"}), 400
            return jsonify({"results": self.embeds.verify_all()})

        @app.route("/api/cleanup/scan", methods=["GET"])
        def api_cleanup_scan():
            minutes = int(request.args.get("minutes", 120))
            if not self.cleanup:
                return jsonify({"error": "cleanup disabled"}), 400
            return jsonify({"items": self.cleanup.find(minutes)})

        @app.route("/api/cleanup/delete", methods=["POST"])
        def api_cleanup_delete():
            if not self.cleanup:
                return jsonify({"error": "cleanup disabled"}), 400
            body = request.get_json(silent=True) or {}
            paths = body.get("paths", [])
            removed, failed = self.cleanup.delete(paths)
            return jsonify({"removed": removed, "failed": failed})

        # ---- desktop app control endpoints ----

        @app.route("/api/monitors")
        def api_monitors():
            out = {}
            for name, mon in self.monitors.items():
                out[name] = {
                    "status": self._mon_status(mon),
                    "class": type(mon).__name__,
                }
            return jsonify({"monitors": out, "ipblock_enabled": bool(self.ipblock and self.ipblock.enabled)})

        @app.route("/api/monitors/<name>", methods=["POST"])
        def api_monitor_toggle(name):
            body = request.get_json(silent=True) or {}
            enabled = bool(body.get("enabled", True))
            if name not in self.monitors:
                return jsonify({"error": "unknown monitor"}), 404
            mon = self.monitors[name]
            try:
                if enabled:
                    stop_flag = getattr(mon, "_stop", None)
                    if stop_flag is not None:
                        stop_flag.clear()
                    mon.start()
                else:
                    mon.stop()
            except Exception as exc:
                return jsonify({"ok": False, "error": str(exc)}), 500
            ok = self._persist_config(f"{name}_monitor", {"enabled": enabled})
            return jsonify({"ok": True, "name": name, "enabled": enabled, "saved": ok})

        @app.route("/api/control/state")
        def api_control_state():
            from . import control as ctl

            st = ctl.status()
            st["monitors_running"] = sum(
                1 for m in self.monitors.values() if self._mon_status(m) == "running"
            )
            st["monitors_total"] = len(self.monitors)
            if self.runtime is not None:
                st["mode"] = self.runtime.mode
            return jsonify(st)

        def _runtime_action(action):
            if self.runtime is None:
                return jsonify({"ok": False, "error": "runtime control unavailable"}), 503
            body = request.get_json(silent=True) or {}
            reason = (body.get("reason") or f"{action} requested").strip()
            try:
                getattr(self.runtime, action)(reason)
            except Exception as exc:
                return jsonify({"ok": False, "error": str(exc)}), 500
            return jsonify({"ok": True, "mode": self.runtime.mode, "action": action})

        @app.route("/api/control/pause", methods=["POST"])
        def api_control_pause():
            return _runtime_action("pause")

        @app.route("/api/control/resume", methods=["POST"])
        def api_control_resume():
            return _runtime_action("resume")

        @app.route("/api/control/stop", methods=["POST"])
        def api_control_stop():
            return _runtime_action("shutdown")

        @app.route("/api/control/restart", methods=["POST"])
        def api_control_restart():
            return _runtime_action("restart")

        @app.route("/api/lock", methods=["POST"])
        def api_lock():
            try:
                from .panic import lock_workstation
                lock_workstation()
                return jsonify({"ok": True, "locked": True})
            except Exception as exc:
                return jsonify({"ok": False, "error": str(exc)}), 500

        @app.route("/api/panic", methods=["POST"])
        def api_panic():
            try:
                if self.alerts:
                    event = {"src_host": "local", "src_port": "-", "dst_port": "-",
                             "local_time": "", "ts": ""}
                    from datetime import datetime
                    self.alerts.send(
                        event, "panic:lock", "critical",
                        f"\U0001f6a8 PANIC LOCK triggered from desktop app\n"
                        f"time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                    )
                from .panic import lock_workstation
                lock_workstation()
                return jsonify({"ok": True})
            except Exception as exc:
                return jsonify({"ok": False, "error": str(exc)}), 500

        @app.route("/api/mute_status")
        def api_mute_status():
            muted = sorted(str(m) for m in getattr(self.alerts, "muted", set())) if self.alerts else []
            return jsonify({"muted": muted})

        @app.route("/api/mute", methods=["POST"])
        def api_mute():
            if not self.alerts:
                return jsonify({"error": "alerts not available"}), 503
            body = request.get_json(silent=True) or {}
            cat = (body.get("category") or "").strip().lower()
            if not cat:
                return jsonify({"error": "category required"}), 400
            self.alerts.muted.add(cat)
            self._persist_alerts_mute()
            return jsonify({"ok": True, "muted": sorted(self.alerts.muted)})

        @app.route("/api/unmute", methods=["POST"])
        def api_unmute():
            if not self.alerts:
                return jsonify({"error": "alerts not available"}), 503
            body = request.get_json(silent=True) or {}
            cat = (body.get("category") or "").strip().lower()
            if body.get("all"):
                self.alerts.muted.clear()
            elif cat:
                self.alerts.muted.discard(cat)
            self._persist_alerts_mute()
            return jsonify({"ok": True, "muted": sorted(self.alerts.muted)})

        @app.route("/api/digest", methods=["POST"])
        def api_digest():
            if not self.alerts:
                return jsonify({"error": "alerts not available"}), 503
            try:
                self.alerts.send_digest()
                return jsonify({"ok": True})
            except Exception as exc:
                return jsonify({"ok": False, "error": str(exc)}), 500

        @app.route("/api/screenshot")
        def api_screenshot():
            if not self.alerts:
                return jsonify({"error": "alerts not available"}), 503
            try:
                shot = self.alerts._grab_screenshot()
                if not shot:
                    return jsonify({"error": "screenshot failed"}), 500
                return app.response_class(shot, mimetype="image/jpeg")
            except Exception as exc:
                return jsonify({"error": str(exc)}), 500

        @app.route("/api/ipblock/blocked")
        def api_ipblock_blocked():
            try:
                return jsonify({"blocked": self._blocked_ips(ttl=10)})
            except Exception as exc:
                return jsonify({"error": str(exc)}), 500

        @app.route("/api/ipblock/block", methods=["POST"])
        def api_ipblock_block():
            if not self.ipblock:
                return jsonify({"error": "ipblocker not available"}), 503
            body = request.get_json(silent=True) or {}
            ip = (body.get("ip") or "").strip()
            if not ip:
                return jsonify({"error": "ip required"}), 400
            self.ipblock._block(ip, body.get("fails", 99))
            return jsonify({"ok": True, "ip": ip})

        @app.route("/api/ipblock/remove", methods=["POST"])
        def api_ipblock_remove():
            if not self.ipblock:
                return jsonify({"error": "ipblocker not available"}), 503
            body = request.get_json(silent=True) or {}
            ip = (body.get("ip") or "").strip()
            if not ip:
                return jsonify({"error": "ip required"}), 400
            rule = f'CanaryBlock_{ip.replace(".", "_")}'
            from ._winproc import run as _proc_run
            r = _proc_run(["netsh", "advfirewall", "firewall", "delete",
                           "rule", f"name={rule}"],
                          capture_output=True, timeout=15).returncode
            self.ipblock._blocked.pop(ip, None)
            return jsonify({"ok": True, "ip": ip, "removed": r == 0})

    # ---- helpers ----

    def _mon_status(self, mon):
        try:
            if mon is None:
                return "missing"
            stop_flag = getattr(mon, "_stop", None)
            if stop_flag is not None and stop_flag.is_set():
                return "stopped"
            thr = getattr(mon, "_thread", None)
            if thr is not None:
                return "running" if thr.is_alive() else "dead"
            obs = getattr(mon, "_obs", None)
            if obs is not None:
                return "running" if obs.is_alive() else "dead"
            return "running"
        except Exception:
            return "unknown"

    def _persist_config(self, section, data):
        """Persist a small change into config.json (section.enabled etc.)."""
        try:
            with open(self.config.path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
            raw.setdefault(section, {}).update(data)
            with open(self.config.path, "w", encoding="utf-8") as fh:
                json.dump(raw, fh, indent=4, ensure_ascii=False)
            self.config.data = raw
            return True
        except Exception as exc:
            self.logger(f"[webapp] config persist failed: {exc}")
            return False

    def _persist_alerts_mute(self):
        muted = sorted(str(m) for m in getattr(self.alerts, "muted", set()))
        self._persist_config("alerts", {"mute_categories": muted})

    def run(self, host=None, port=None):
        host = host or self.config.get("dashboard", "host", default="127.0.0.1")
        port = port or int(self.config.get("dashboard", "port", default=8080))
        threading.Thread(target=self.app.run, kwargs={"host": host, "port": port, "debug": False, "use_reloader": False}, daemon=True).start()
        self.logger(f"[dashboard] http://{host}:{port}")