import hashlib
import threading
import time
from datetime import datetime

from .config import get_store

CF_UNICODETEXT = 13

DEFAULT_KEYWORDS = ["password", "passwd", "pwd", "token", "secret", "api_key",
                    "apikey", "login", "mot de passe", "sk-", "ghp_", "AKIA"]


def _get_clipboard_text():
    try:
        import ctypes
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32
        # 64-bit safe signatures - without these, pointers get truncated to 32-bit
        user32.GetClipboardData.restype = ctypes.c_void_p
        user32.GetClipboardData.argtypes = [ctypes.c_uint]
        kernel32.GlobalLock.restype = ctypes.c_void_p
        kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
        kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
        if not user32.OpenClipboard(None):
            return None
        try:
            handle = user32.GetClipboardData(CF_UNICODETEXT)
            if not handle:
                return None
            ptr = kernel32.GlobalLock(handle)
            if not ptr:
                return None
            try:
                return ctypes.wstring_at(ptr)
            finally:
                kernel32.GlobalUnlock(handle)
        finally:
            user32.CloseClipboard()
    except Exception:
        return None


class ClipboardMonitor:
    """Capture clipboard changes; alert when sensitive keywords appear.

    Every change is recorded silently to the DB. Telegram alerts fire only
    for text matching configured keywords (mode='keywords') or for every
    change (mode='all', cooldown-limited).
    """

    def __init__(self, config, alerts=None, logger=None):
        self.config = config
        self.logger = logger or print
        self.store = get_store(config)
        self.alerts = alerts
        self.poll = float(config.get("clipboard_monitor", "poll_seconds", default=1.5))
        self.mode = config.get("clipboard_monitor", "mode", default="keywords")
        kws = config.get("clipboard_monitor", "keywords", default=None) or DEFAULT_KEYWORDS
        self.keywords = [k.lower() for k in kws]
        self.cooldown = int(config.get("clipboard_monitor", "cooldown_seconds", default=20))
        self._stop = threading.Event()
        self._thread = None
        self._last_hash = None
        self._cd = {}

    def _within(self, key):
        now = time.monotonic()
        if now - self._cd.get(key, 0) < self.cooldown:
            return True
        self._cd[key] = now
        return False

    def _handle(self, text):
        digest = hashlib.md5(text.encode("utf-8", "ignore")).hexdigest()
        if digest == self._last_hash:
            return
        self._last_hash = digest

        low = text.lower()
        hit = next((k for k in self.keywords if k in low), "")
        preview = text[:200].replace("\r", " ").replace("\n", " ")
        self.store.insert_clipboard_event(preview, len(text), hit)
        label = f"keyword={hit}" if hit else "change"
        self.logger(f"[clip] captured ({len(text)} chars, {label})")

        if not self.alerts:
            return
        if self.mode == "keywords" and not hit:
            return
        if self._within(f"clip:{digest[:8]}"):
            return
        sev = "high" if hit else "medium"
        icon = "\U0001f511" if hit else "\U0001f4cb"
        title = f"{icon} CLIPBOARD {'SENSITIVE DATA: ' + hit if hit else 'CHANGED'}"
        msg = (
            f"{title}\n"
            f"chars: {len(text)}\n"
            f"content: {preview}{'...' if len(text) > 200 else ''}\n"
            f"time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        event = {"src_host": "local", "src_port": -1, "dst_port": -1,
                 "local_time": "", "ts": ""}
        self.alerts.send(event, "clip:found" if hit else "clip:change", sev, msg)

    def _run(self):
        while not self._stop.is_set():
            text = _get_clipboard_text()
            if text and text.strip():
                try:
                    self._handle(text)
                except Exception as exc:
                    self.logger(f"[clip] error: {exc}")
            self._stop.wait(self.poll)

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self.logger(f"[clip] monitoring clipboard (mode={self.mode})")

    def stop(self):
        self._stop.set()