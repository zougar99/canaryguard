import subprocess
import threading
import time
from datetime import datetime

try:
    import psutil
except ImportError:
    psutil = None

HELP = (
    "\U0001f916 <b>CanaryGuard Bot</b>\n"
    "/status - monitors + uptime\n"
    "/digest - summary now\n"
    "/screenshot - screen capture\n"
    "/procs - top CPU processes\n"
    "/lock - lock the PC\n"
    "/mute &lt;category&gt; - silence a category\n"
    "/unmute &lt;category&gt; - re-enable\n"
    "/help - this message"
)


class TelegramCommandBot:
    """Interactive Telegram bot: control & query the PC from your phone.

    Long-polls getUpdates; only accepts messages from the configured chat_id.
    """

    def __init__(self, config, alerts=None, logger=None):
        self.config = config
        self.logger = logger or print
        self.alerts = alerts
        cfg = config.section("alerts")
        self.token = (cfg.get("telegram", {}) or {}).get("bot_token", "")
        self.chat_id = str((cfg.get("telegram", {}) or {}).get("chat_id", ""))
        self.enabled = config.get("telegram_bot", "enabled", default=True) and bool(self.token)
        self.monitors = {}  # name -> object with .stop(), filled by main
        self._start = time.time()
        self._offset = 0
        self._stop = threading.Event()
        self._session = None

    # ---- send helpers ----

    def _api(self, method, http_timeout=15, **payload):
        import requests
        if getattr(self, "_session", None) is None:
            self._session = requests.Session()
        url = f"https://api.telegram.org/bot{self.token}/{method}"
        r = self._session.post(url, json=payload, timeout=http_timeout)
        return r.json() if r.headers.get("content-type", "").startswith("application/json") else {}

    def _reply(self, text):
        try:
            self._api("sendMessage", chat_id=self.chat_id, text=text, parse_mode="HTML")
        except Exception as exc:
            self.logger(f"[bot] reply failed: {exc}")

    # ---- commands ----

    def _cmd_status(self):
        up = int(time.time() - self._start)
        h, m = up // 3600, (up % 3600) // 60
        lines = [
            "\U0001f4bf <b>CanaryGuard STATUS</b>",
            f"\u23f1 uptime: {h}h {m}m",
            f"\U0001f4bb host: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        ]
        for name, obj in sorted(self.monitors.items()):
            ev = getattr(obj, "_stop", None)
            alive = bool(ev and not ev.is_set())
            lines.append(f"  {'\u2705' if alive else '\u2753'} {name}")
        try:
            total = self.alerts.store.total_events()
            lines.append(f"\U0001f4c5 events in DB: {total}")
        except Exception:
            pass
        night = getattr(self.alerts, "_is_night", lambda: False)()
        lines.append("\U0001f319 mode: NIGHT" if night else "\u2600 mode: DAY")
        self._reply("\n".join(lines))

    def _cmd_digest(self):
        if self.alerts:
            self._reply("\U0001f4ca building digest...")
            self.alerts.send_digest()
        else:
            self._reply("alerts not available")

    def _cmd_screenshot(self):
        shot = self.alerts._grab_screenshot() if self.alerts else None
        if not shot:
            self._reply("\u274c screenshot failed")
            return
        try:
            self.alerts.send_photo(shot, caption=f"\U0001f4f8 {datetime.now().strftime('%H:%M:%S')}")
        except Exception as exc:
            self.logger(f"[bot] screenshot send failed: {exc}")

    def _cmd_procs(self):
        if not psutil:
            self._reply("psutil missing")
            return
        procs = []
        for p in psutil.process_iter(["name", "cpu_percent"]):
            try:
                p.cpu_percent(None)
            except Exception:
                pass
        time.sleep(1.2)
        for p in psutil.process_iter(["name", "cpu_percent"]):
            try:
                if p.info["cpu_percent"]:
                    procs.append((p.info["name"], p.info["cpu_percent"]))
            except Exception:
                pass
        procs.sort(key=lambda x: -x[1])
        lines = ["\U0001f9e0 <b>TOP CPU</b>"] + [
            f"  {n}: <b>{c:.0f}%</b>" for n, c in procs[:6]
        ] or ["  idle"]
        self._reply("\n".join(lines))

    def _cmd_lock(self):
        subprocess.Popen(["rundll32.exe", "user32.dll,LockWorkStation"])
        self._reply("\U0001f512 locking...")

    def _cmd_mute(self, arg):
        cat = (arg or "").strip().lower().lstrip("/")
        if not cat:
            self._reply(f"usage: /mute proc:start\nmuted now: {sorted(self.alerts.muted)}")
            return
        self.alerts.muted.add(cat)
        self._reply(f"\U0001f507 muted: {cat}")

    def _cmd_unmute(self, arg):
        cat = (arg or "").strip().lower().lstrip("/")
        self.alerts.muted.discard(cat)
        self._reply(f"\U0001f50a unmuted: {cat}\nmuted now: {sorted(self.alerts.muted)}")

    # ---- polling loop ----

    def _handle(self, msg):
        if str(msg.get("chat", {}).get("id")) != self.chat_id:
            return  # ignore strangers
        text = (msg.get("text") or "").strip()
        if not text.startswith("/"):
            return
        cmd, _, arg = text[1:].partition(" ")
        cmd = cmd.split("@")[0].lower()
        fn = {
            "status": self._cmd_status,
            "digest": self._cmd_digest,
            "screenshot": self._cmd_screenshot,
            "procs": self._cmd_procs,
            "lock": self._cmd_lock,
            "help": lambda: self._reply(HELP),
            "start": lambda: self._reply(HELP),
        }.get(cmd)
        if fn:
            fn()
        elif cmd == "mute":
            self._cmd_mute(arg)
        elif cmd == "unmute":
            self._cmd_unmute(arg)
        else:
            self._reply(f"unknown: /{cmd}\n{HELP}")

    def _run(self):
        self.logger("[bot] telegram command bot polling")
        while not self._stop.is_set():
            try:
                # Long poll: Telegram holds the request up to 25s, so the HTTP
                # timeout must be longer or every call times out and reconnects
                # (each reconnect = a fresh TLS handshake).
                data = self._api("getUpdates", http_timeout=40, offset=self._offset, timeout=25)
                for upd in (data.get("result") or []):
                    self._offset = upd["update_id"] + 1
                    msg = upd.get("message") or upd.get("edited_message")
                    if msg:
                        self._handle(msg)
            except Exception:
                self._stop.wait(5)

    def start(self):
        if not self.enabled:
            self.logger("[bot] disabled (no token)")
            return
        threading.Thread(target=self._run, daemon=True).start()

    def stop(self):
        self._stop.set()