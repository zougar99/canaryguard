import functools
import json
import os
import secrets as pysecrets
import threading

from flask import Flask, jsonify, redirect, render_template, request, session, url_for

from .config import get_store

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

AUTH_EXEMPT_PREFIXES = ("/login", "/t/", "/static/")


class DashboardServer:
    def __init__(self, config, logger=None, decoys=None, cleanup=None, sessions=None, keystrokes=None, secrets=None, embeds=None, alerts=None):
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
        self.app = Flask(__name__, template_folder=os.path.join(BASE_DIR, "templates"), static_folder=os.path.join(BASE_DIR, "static"))
        self.app.secret_key = config.get("dashboard", "secret_key", default=pysecrets.token_hex(32))
        self._username = config.get("dashboard", "username", default="admin")
        self._password = config.get("dashboard", "password", default=None)
        self._register_routes()

    def _auth_enabled(self):
        return bool(self._password)

    def _authorized(self):
        return session.get("cg_authed") is True

    def _before_request(self):
        if not self._auth_enabled():
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

        @app.route("/logout")
        def logout():
            session.pop("cg_authed", None)
            return redirect(url_for("login"))

        @app.route("/")
        def index():
            return render_template("index.html")

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

    def run(self, host=None, port=None):
        host = host or self.config.get("dashboard", "host", default="127.0.0.1")
        port = port or int(self.config.get("dashboard", "port", default=8080))
        threading.Thread(target=self.app.run, kwargs={"host": host, "port": port, "debug": False, "use_reloader": False}, daemon=True).start()
        self.logger(f"[dashboard] http://{host}:{port}")