"""CanaryGuard control supervisor (always on).

This process is deliberately tiny and independent from main.py: it only talks
to Telegram and to the runtime control module. That is what makes /start work
even after the main service has been fully stopped, and it means /stop never
takes the controller down with it.

Telegram commands (slash or plain word):
    status | start | stop | sleep (pause) | resume | restart
    digest | screenshot | lock | procs | mute <cat> | unmute <cat> | id | help

Security: commands are accepted only from chats listed in
telegram_bot.allowed_chats (defaults to alerts.telegram.chat_id). In groups and
supergroups, telegram_bot.admin_user_ids must contain the sender when set.
"""

import html
import json
import os
import sys
import threading
import time
from datetime import datetime

BASE = os.path.dirname(os.path.abspath(__file__))
if BASE not in sys.path:
    sys.path.insert(0, BASE)

import requests  # noqa: E402

from canaryguard import control as ctl  # noqa: E402
from canaryguard.config import Config  # noqa: E402

LOG_FILE = os.path.join(BASE, "control.log")
LOCK_FILE = os.path.join(BASE, "cgctl.lock")
API = "http://127.0.0.1:8080"

HELP = (
    "\U0001f916 <b>CanaryGuard Control</b>\n"
    "/status - state, uptime, monitors\n"
    "/start - start the service\n"
    "/stop - stop the service\n"
    "/sleep - pause all monitors (dashboard stays up)\n"
    "/resume - resume monitors\n"
    "/restart - restart the service\n"
    "/digest - send a summary now\n"
    "/screenshot - screen capture\n"
    "/lock - lock the PC\n"
    "/procs - top CPU processes\n"
    "/mute &lt;category&gt; - silence a category\n"
    "/unmute &lt;category&gt; - re-enable\n"
    "/id - show this chat id (for allowed_chats)\n"
    "/help - this message"
)

ALIASES = {
    "status": "status", "state": "status", "info": "status",
    "start": "start", "on": "start", "run": "start",
    "stop": "stop", "off": "stop", "halt": "stop", "kill": "stop",
    "sleep": "pause", "pause": "pause", "snooze": "pause",
    "resume": "resume", "wake": "resume", "continue": "resume",
    "restart": "restart", "reboot": "restart",
    "digest": "digest", "summary": "digest",
    "screenshot": "screenshot", "screen": "screenshot", "shot": "screenshot",
    "lock": "lock",
    "procs": "procs", "top": "procs",
    "id": "id", "chatid": "id",
    "help": "help", "commands": "help", "start?": "help",
}


def log(line):
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as fh:
            fh.write(f"{datetime.now():%Y-%m-%d %H:%M:%S} {line}\n")
    except Exception:
        pass


class ControlSupervisor:
    def __init__(self):
        self.config = Config.load()
        alerts_cfg = self.config.section("alerts")
        tg = alerts_cfg.get("telegram", {}) or {}
        self.token = tg.get("bot_token", "") or ""
        self.chat_id = str(tg.get("chat_id", "") or "")
        bot_cfg = self.config.section("telegram_bot")
        self.enabled = bool(self.token)
        raw_allowed = bot_cfg.get("allowed_chats", None) or []
        allowed = {str(x).strip() for x in raw_allowed if str(x).strip()}
        if self.chat_id:
            allowed.add(self.chat_id)
        self.allowed = allowed
        self.admin_ids = {str(x).strip() for x in (bot_cfg.get("admin_user_ids", None) or [])}
        self.session = requests.Session()
        self.offset = 0
        self.started = time.time()

    # ------------------------------------------------------------ telegram

    def api(self, method, http_timeout=40, **payload):
        url = f"https://api.telegram.org/bot{self.token}/{method}"
        resp = self.session.post(url, json=payload, timeout=http_timeout)
        try:
            return resp.json()
        except Exception:
            return {}

    def reply(self, chat_id, text, thread_id=None):
        payload = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        if thread_id:
            payload["message_thread_id"] = thread_id
        try:
            self.api("sendMessage", chat_id=chat_id, **{k: v for k, v in payload.items() if k != "chat_id"})
        except Exception as exc:
            log(f"reply failed: {exc}")

    def send_photo(self, chat_id, data, caption=""):
        url = f"https://api.telegram.org/bot{self.token}/sendPhoto"
        self.session.post(url, data={"chat_id": chat_id, "caption": caption[:900]},
                          files={"photo": ("shot.jpg", data)}, timeout=30)

    # ------------------------------------------------------------ auth

    def chat_allowed(self, chat):
        cid = str(chat.get("id"))
        uname = (chat.get("username") or "").lower()
        if cid in self.allowed:
            return True
        if uname and f"@{uname}" in {a.lower() for a in self.allowed}:
            return True
        return False

    def sender_allowed(self, msg, chat):
        ctype = chat.get("type")
        if ctype in ("group", "supergroup") and self.admin_ids:
            sender = msg.get("from") or {}
            return str(sender.get("id")) in self.admin_ids
        return True

    # ------------------------------------------------------------ commands

    def cmd_status(self, chat_id, thread):
        st = ctl.status()
        mode = st.get("mode", "?")
        icon = {"running": "\u2705", "paused": "\u23f8", "stopped": "\u23f9",
                "starting": "\u23f3", "restarting": "\U0001f504"}.get(mode, "\u2753")
        lines = [
            f"{icon} <b>CanaryGuard: {html.escape(str(mode).upper())}</b>",
            f"\U0001f5a5 host: {html.escape(os.environ.get('COMPUTERNAME', 'PC'))}",
            f"\u23f1 uptime: {ctl.human_uptime(st.get('uptime_seconds'))}",
            f"\U0001f310 dashboard: {'online' if st.get('dashboard') else 'offline'}",
            f"\U0001f9e9 pids: {', '.join(str(p) for p in st.get('pids', [])) or '-'}",
        ]
        if st.get("reason"):
            lines.append(f"\U0001f4dd reason: {html.escape(str(st['reason']))}")
        if st.get("stopped_flag"):
            lines.append("\u26a0 stop flag set (watchdog will not revive)")
        try:
            stats = self.session.get(f"{API}/api/stats", timeout=4).json()
            lines.append(f"\U0001f4c5 events: {stats.get('total', '?')} | creds: {stats.get('creds', '?')}")
            mon = self.session.get(f"{API}/api/monitors", timeout=4).json().get("monitors", {})
            alive = sum(1 for m in mon.values() if m.get("status") == "running")
            lines.append(f"\U0001f6e1 monitors: {alive}/{len(mon)} running")
        except Exception:
            lines.append("\U0001f6e1 monitors: dashboard offline")
        self.reply(chat_id, "\n".join(lines), thread)

    def cmd_start(self, chat_id, thread):
        ok, msg = ctl.start_stack("telegram /start")
        log(f"start -> {ok} {msg}")
        if ok:
            self.reply(chat_id, "\u25b6 <b>Starting CanaryGuard...</b>\n"
                                 "I will confirm once the dashboard answers.", thread)
            threading.Thread(target=self._confirm_up, args=(chat_id, thread), daemon=True).start()
        else:
            self.reply(chat_id, f"\u274c start failed: {html.escape(msg)}", thread)

    def _confirm_up(self, chat_id, thread, tries=30):
        for _ in range(tries):
            time.sleep(1)
            if ctl.port_open():
                self.reply(chat_id, "\u2705 <b>CanaryGuard is UP</b>\ndashboard online.", thread)
                return
        self.reply(chat_id, "\u26a0 started, but the dashboard is still offline. "
                             "check guard.err.log", thread)

    def cmd_stop(self, chat_id, thread):
        self.reply(chat_id, "\u23f9 <b>Stopping CanaryGuard...</b>\n"
                             "watchdog will stay quiet until /start.", thread)
        ok, msg = ctl.stop_stack("telegram /stop")
        log(f"stop -> {ok} {msg}")
        self.reply(chat_id, f"\u23f9 <b>STOPPED</b>\n{html.escape(msg)}\n"
                             f"send /start to bring it back.", thread)

    def cmd_pause(self, chat_id, thread):
        ok, msg = ctl.pause_stack("telegram /sleep")
        log(f"pause -> {ok} {msg}")
        self.reply(chat_id, ("\u23f8 <b>SLEEP</b> - monitors paused, dashboard online."
                             if ok else f"\u274c {html.escape(msg)}"), thread)

    def cmd_resume(self, chat_id, thread):
        ok, msg = ctl.resume_stack("telegram /resume")
        log(f"resume -> {ok} {msg}")
        self.reply(chat_id, ("\u25b6 <b>RESUMED</b> - all monitors running."
                             if ok else f"\u274c {html.escape(msg)}"), thread)

    def cmd_restart(self, chat_id, thread):
        ok, msg = ctl.restart_stack("telegram /restart")
        log(f"restart -> {ok} {msg}")
        if ok:
            self.reply(chat_id, "\U0001f504 <b>Restarting...</b>", thread)
            threading.Thread(target=self._confirm_up, args=(chat_id, thread), daemon=True).start()
        else:
            self.reply(chat_id, f"\u274c restart failed: {html.escape(msg)}", thread)

    def cmd_digest(self, chat_id, thread):
        try:
            self.session.post(f"{API}/api/digest", timeout=15)
            self.reply(chat_id, "\U0001f4ca digest sent.", thread)
        except Exception as exc:
            self.reply(chat_id, f"\u274c digest failed: {html.escape(str(exc))}", thread)

    def cmd_screenshot(self, chat_id, thread):
        try:
            resp = self.session.get(f"{API}/api/screenshot", timeout=20)
            if resp.ok and resp.content:
                self.send_photo(chat_id, resp.content,
                                caption=f"\U0001f4f8 {datetime.now():%H:%M:%S}")
                return
            self.reply(chat_id, "\u274c screenshot failed", thread)
        except Exception as exc:
            self.reply(chat_id, f"\u274c screenshot failed: {html.escape(str(exc))}", thread)

    def cmd_lock(self, chat_id, thread):
        try:
            self.session.post(f"{API}/api/lock", timeout=10)
            self.reply(chat_id, "\U0001f512 locking the PC...", thread)
        except Exception as exc:
            self.reply(chat_id, f"\u274c lock failed: {html.escape(str(exc))}", thread)

    def cmd_procs(self, chat_id, thread):
        try:
            import psutil
        except ImportError:
            self.reply(chat_id, "psutil missing", thread)
            return
        rows = []
        for proc in psutil.process_iter(["name", "cpu_percent"]):
            try:
                proc.cpu_percent(None)
            except Exception:
                pass
        time.sleep(1.0)
        for proc in psutil.process_iter(["name", "cpu_percent"]):
            try:
                cpu = proc.info.get("cpu_percent") or 0
                if cpu > 0:
                    rows.append((proc.info.get("name") or "?", cpu))
            except Exception:
                continue
        rows.sort(key=lambda item: -item[1])
        body = "\n".join(f"  {html.escape(n)}: <b>{c:.0f}%</b>" for n, c in rows[:8]) or "  idle"
        self.reply(chat_id, "\U0001f9e0 <b>TOP CPU</b>\n" + body, thread)

    def cmd_mute(self, chat_id, thread, arg, on=True):
        cat = (arg or "").strip().lower()
        if not cat:
            self.reply(chat_id, "usage: /mute proc:start", thread)
            return
        path = "/api/mute" if on else "/api/unmute"
        try:
            self.session.post(f"{API}{path}", json={"category": cat}, timeout=8)
            self.reply(chat_id, f"{'\U0001f507 muted' if on else '\U0001f50a unmuted'}: "
                                 f"{html.escape(cat)}", thread)
        except Exception as exc:
            self.reply(chat_id, f"\u274c {html.escape(str(exc))}", thread)

    def cmd_id(self, chat_id, thread, chat, msg):
        sender = msg.get("from") or {}
        lines = [
            "<b>chat</b>",
            f"  id: <code>{chat.get('id')}</code>",
            f"  type: {chat.get('type')}",
            f"  title: {html.escape(str(chat.get('title') or chat.get('username') or '-'))}",
            f"  allowed now: {'yes' if self.chat_allowed(chat) else 'no'}",
            "<b>sender</b>",
            f"  id: <code>{sender.get('id', '-')}</code>",
            f"  name: {html.escape(str(sender.get('first_name') or '-'))}",
        ]
        self.reply(chat_id, "\n".join(lines), thread)

    # ------------------------------------------------------------ dispatch

    def handle(self, msg):
        chat = msg.get("chat") or {}
        if not chat or chat.get("type") == "private" and False:
            return
        sender = msg.get("from") or {}
        if sender.get("is_bot"):
            return
        text = (msg.get("text") or "").strip()
        if not text:
            return
        raw = text[1:] if text.startswith("/") else text
        cmd, _, arg = raw.partition(" ")
        cmd = cmd.split("@")[0].lower().strip()
        action = ALIASES.get(cmd)
        if not action:
            return  # ignore ordinary conversation
        if not self.chat_allowed(chat):
            log(f"denied chat={chat.get('id')} user={sender.get('id')} cmd={cmd}")
            return
        if not self.sender_allowed(msg, chat):
            log(f"denied sender={sender.get('id')} chat={chat.get('id')} cmd={cmd}")
            self.reply(chat.get("id"), "\u26d4 not allowed for this user", msg.get("message_thread_id"))
            return
        log(f"cmd={cmd} chat={chat.get('id')} user={sender.get('id')}")
        chat_id = chat.get("id")
        thread = msg.get("message_thread_id")
        handlers = {
            "status": lambda: self.cmd_status(chat_id, thread),
            "start": lambda: self.cmd_start(chat_id, thread),
            "stop": lambda: self.cmd_stop(chat_id, thread),
            "pause": lambda: self.cmd_pause(chat_id, thread),
            "resume": lambda: self.cmd_resume(chat_id, thread),
            "restart": lambda: self.cmd_restart(chat_id, thread),
            "digest": lambda: self.cmd_digest(chat_id, thread),
            "screenshot": lambda: self.cmd_screenshot(chat_id, thread),
            "lock": lambda: self.cmd_lock(chat_id, thread),
            "procs": lambda: self.cmd_procs(chat_id, thread),
            "id": lambda: self.cmd_id(chat_id, thread, chat, msg),
            "help": lambda: self.reply(chat_id, HELP, thread),
        }
        try:
            if cmd in ("mute", "unmute"):
                self.cmd_mute(chat_id, thread, arg, on=(cmd == "mute"))
            elif action in handlers:
                handlers[action]()
        except Exception as exc:
            log(f"handler error cmd={cmd}: {exc}")
            self.reply(chat_id, f"\u274c error: {html.escape(str(exc))}", thread)

    # ------------------------------------------------------------ loop

    def run(self):
        log(f"supervisor started (allowed_chats={sorted(self.allowed)}, "
            f"admins={sorted(self.admin_ids)})")
        backoff = 5
        while True:
            try:
                data = self.api("getUpdates", http_timeout=40, offset=self.offset, timeout=25)
                if not data.get("ok"):
                    err = data.get("description", "unknown")
                    log(f"getUpdates not ok: {err}")
                    if "409" in str(err) or "Conflict" in str(err):
                        log("another poller is running - waiting")
                        time.sleep(10)
                        continue
                    time.sleep(backoff)
                    continue
                backoff = 5
                for upd in data.get("result") or []:
                    self.offset = max(self.offset, upd.get("update_id", 0) + 1)
                    msg = (upd.get("message") or upd.get("edited_message")
                           or upd.get("channel_post") or upd.get("edited_channel_post"))
                    if msg:
                        self.handle(msg)
            except Exception as exc:
                log(f"loop error: {exc}")
                time.sleep(backoff)
                backoff = min(60, backoff * 2)


def _single_instance():
    """Refuse to run two supervisors (they would fight over getUpdates)."""
    try:
        import msvcrt

        fh = open(LOCK_FILE, "a+")
        msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
        return fh
    except Exception:
        return None


def main():
    handle = _single_instance()
    if handle is None:
        log("another supervisor is already running - exiting")
        return
    sup = ControlSupervisor()
    if not sup.enabled:
        log("no telegram bot token configured - supervisor idle")
        while True:
            time.sleep(300)
    sup.run()


if __name__ == "__main__":
    main()
