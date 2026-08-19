import ctypes
import ctypes.wintypes as wt
import threading
import time
from datetime import datetime

from .config import get_store

WH_KEYBOARD_LL = 13
WM_KEYDOWN = 0x0100
WM_SYSKEYDOWN = 0x0104
WM_KEYUP = 0x0101
WM_SYSKEYUP = 0x0105

ctypes.windll.user32.CallNextHookEx.argtypes = [
    ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_void_p,
]
ctypes.windll.user32.CallNextHookEx.restype = ctypes.c_long
ctypes.windll.user32.SetWindowsHookExW.argtypes = [
    ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong,
]
ctypes.windll.user32.SetWindowsHookExW.restype = ctypes.c_void_p

# Virtual key -> printable label
SPECIAL_KEYS = {
    0x08: "[BACKSPACE]", 0x09: "[TAB]", 0x0D: "[ENTER]", 0x1B: "[ESC]",
    0x20: "[SPACE]", 0x2E: "[DEL]", 0x24: "[HOME]", 0x23: "[END]",
    0x21: "[PGUP]", 0x22: "[PGDN]", 0x25: "[LEFT]", 0x26: "[UP]",
    0x27: "[RIGHT]", 0x28: "[DOWN]", 0x2C: "[PRTSC]", 0x2D: "[INS]",
    0x14: "[CAPS]", 0x5B: "[WIN]", 0x5C: "[WIN]", 0x13: "[PAUSE]",
    0x91: "[SCRLK]", 0x90: "[NUMLK]", 0x2F: "[HELP]",
}

STATE_FILE = None  # not persisted; DB is the store


class KeyLogger:
    """Low-level keyboard hook for the LOCAL session.

    Records every keystroke typed into the foreground window on this PC
    together with the window title, so the user can see what an intruder
    (e.g. over RDP into their own machine) types.  The hook only runs in
    the session where CanaryGuard is launched.
    """

    def __init__(self, config, alerts=None, logger=None, buffer_max=200, flush_secs=5.0):
        self.config = config
        self.logger = logger or print
        self.store = get_store(config)
        self.alerts = alerts
        self.enabled = config.get("protect", "keylogger", default=True)
        self.buffer_max = int(config.get("protect", "key_buffer_max", default=200))
        self.flush_secs = float(config.get("protect", "key_flush_secs", default=5.0))
        self.sensitive = config.get("protect", "sensitive_keywords", default=[])
        self._buffer = []
        self._current_window = ""
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        self._hook = None
        self._pump = None
        self._proc = None

    # ---------- helpers ----------

    @staticmethod
    def _window_title():
        try:
            hwnd = ctypes.windll.user32.GetForegroundWindow()
            length = ctypes.windll.user32.GetWindowTextLengthW(hwnd) + 1
            buf = ctypes.create_unicode_buffer(length)
            ctypes.windll.user32.GetWindowTextW(hwnd, buf, length)
            return buf.value[:80]
        except Exception:
            return ""

    @staticmethod
    def _key_char(vk, caps, shift):
        # map letter / number keys through keyboard layout via ToUnicodeEx
        try:
            state = (ctypes.c_ubyte * 256)()
            state[0x10] = 0x80 if shift else 0
            state[0x14] = 0x80 if caps else 0
            buf = (ctypes.c_wchar * 8)()
            res = ctypes.windll.user32.ToUnicodeEx(vk, 0, state, buf, 8, 0, 0)
            if res == 1:
                return buf[0]
            if res == -1:
                return ""
            if res > 1:
                return "".join(buf[i] for i in range(res))
        except Exception:
            pass
        return ""

    # ---------- hook ----------

    def _hook_proc(self, n_code, w_param, l_param):
        if n_code >= 0:
            kbs = ctypes.cast(l_param, ctypes.POINTER(KeyboardHookStruct)).contents
            vk = kbs.vkCode
            # only keydown events
            if w_param in (WM_KEYDOWN, WM_SYSKEYDOWN):
                title = self._window_title()
                if vk in SPECIAL_KEYS:
                    char = SPECIAL_KEYS[vk]
                else:
                    shift = ctypes.windll.user32.GetKeyState(0x10) & 0x8000
                    caps = ctypes.windll.user32.GetKeyState(0x14) & 0x0001
                    char = self._key_char(vk, caps, shift)
                if char:
                    with self._lock:
                        if title != self._current_window:
                            if self._current_window:
                                self._buffer.append(f"\n[{title}] ")
                            self._current_window = title
                        self._buffer.append(char)
        return ctypes.windll.user32.CallNextHookEx(self._hook, n_code, w_param, l_param)

    def _pump_loop(self):
        msg = wt.MSG()
        while not self._stop.is_set() and ctypes.windll.user32.GetMessageW(ctypes.byref(msg), 0, 0, 0) != -1:
            ctypes.windll.user32.TranslateMessage(ctypes.byref(msg))
            ctypes.windll.user32.DispatchMessageW(ctypes.byref(msg))

    def _run(self):
        if not self.enabled:
            return
        CMPFUNC = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_int, ctypes.c_int, ctypes.c_void_p)
        self._proc = CMPFUNC(self._hook_proc)
        # initialize the message queue for this thread (required before a
        # WH_KEYBOARD_LL hook; otherwise SetWindowsHookEx fails with err=126)
        msg_init = wt.MSG()
        ctypes.windll.user32.PeekMessageW(ctypes.byref(msg_init), 0, 0, 0, 0x0001)
        # For low-level hooks the hook procedure lives in the current process,
        # so hMod must be NULL (passing the exe module handle causes err=126).
        self._hook = ctypes.windll.user32.SetWindowsHookExW(
            WH_KEYBOARD_LL, self._proc, None, 0
        )
        if not self._hook:
            err = ctypes.windll.kernel32.GetLastError()
            self.logger(f"[keylogger] failed to install hook (err={err})")
            return
        self.logger("[keylogger] capturing local session keys")
        self._hook_ok = True

        # low-level hooks require the message loop on the SAME thread as the hook
        last_flush = time.monotonic()
        msg = wt.MSG()
        while not self._stop.is_set():
            ret = ctypes.windll.user32.PeekMessageW(ctypes.byref(msg), 0, 0, 0, 0x0001)  # PM_NOREMOVE
            if ret:
                ctypes.windll.user32.GetMessageW(ctypes.byref(msg), 0, 0, 0)
                ctypes.windll.user32.TranslateMessage(ctypes.byref(msg))
                ctypes.windll.user32.DispatchMessageW(ctypes.byref(msg))
            else:
                time.sleep(0.005)
            if time.monotonic() - last_flush >= self.flush_secs:
                self.flush()
                last_flush = time.monotonic()
        self.flush()

        if self._hook:
            ctypes.windll.user32.UnhookWindowsHookEx(self._hook)
            self._hook = None

    def flush(self):
        with self._lock:
            if not self._buffer:
                return
            text = "".join(self._buffer)
            window = self._current_window or "?"
            self._buffer = []
            self._current_window = ""

        self.store.insert_keystrokes(window, text)
        low = text.lower()
        for kw in self.sensitive:
            if kw.lower() in low:
                self.logger(f"[keylogger] sensitive keyword matched: {kw}")
                if self.alerts:
                    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    msg = (
                        f"\U0001f511 *Sensitive keyword typed on this PC*\n"
                        f"\U0001f4e1 Trigger: `{kw}`\n"
                        f"\U0001f5a5 Window: `{window}`\n"
                        f"\U0001f4c5 Time: {now}\n"
                        f"\U0001f4dd Captured: `{text[-200:]}`"
                    )
                    event = {"src_host": "", "src_port": -1, "dst_port": -1, "local_time": now, "ts": now}
                    self.alerts.send(event, "keylogger:keyword", "high", msg)

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()


class KeyboardHookStruct(ctypes.Structure):
    _fields_ = [
        ("vkCode", ctypes.c_ulong),
        ("scanCode", ctypes.c_ulong),
        ("flags", ctypes.c_ulong),
        ("time", ctypes.c_ulong),
        ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong)),
    ]