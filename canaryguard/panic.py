import ctypes
import threading
import time
from datetime import datetime

from .config import get_store


def lock_workstation():
    try:
        return ctypes.windll.user32.LockWorkStation() != 0
    except Exception:
        return False


class IdleLocker:
    """Lock the PC after N minutes of no input (keyboard/mouse)."""

    def __init__(self, config, alerts=None, logger=None):
        self.config = config
        self.logger = logger or print
        self.alerts = alerts
        cfg = config.section("panic")
        self.enabled = cfg.get("idle_lock_enabled", True)
        self.timeout_min = float(cfg.get("idle_lock_minutes", 15))
        self.notify = cfg.get("notify_idle_lock", False)
        self._stop = threading.Event()

    @staticmethod
    def _idle_seconds():
        class LASTINPUTINFO(ctypes.Structure):
            _fields_ = [("cbSize", ctypes.c_uint), ("dwTime", ctypes.c_uint)]
        lii = LASTINPUTINFO()
        lii.cbSize = ctypes.sizeof(LASTINPUTINFO)
        if not ctypes.windll.user32.GetLastInputInfo(ctypes.byref(lii)):
            return 0
        return (ctypes.windll.kernel32.GetTickCount() - lii.dwTime) / 1000.0

    def _run(self):
        while not self._stop.is_set():
            time.sleep(20)
            try:
                idle = self._idle_seconds()
                limit = self.timeout_min * 60
                if idle >= limit:
                    if lock_workstation():
                        self.logger(f"[idle] locked PC (idle {int(idle)}s)")
                        if self.alerts and self.notify:
                            msg = f"\U0001f4a4 AUTO-LOCK: PC idle {self.timeout_min} min -> locked"
                            event = {"src_host": "local", "src_port": -1, "dst_port": -1,
                                     "local_time": "", "ts": ""}
                            self.alerts.send(event, "idle:lock", "low", msg)
                    time.sleep(60)  # don't re-fire while user away
            except Exception as exc:
                self.logger(f"[idle] error: {exc}")

    def start(self):
        if not self.enabled:
            self.logger("[idle] idle auto-lock disabled")
            return
        threading.Thread(target=self._run, daemon=True).start()
        self.logger(f"[idle] auto-lock after {self.timeout_min} min idle")

    def stop(self):
        self._stop.set()


class PanicManager:
    """Panic actions: auto-lock on brute-force logins or USB grab-and-run.

    - 3 failed dashboard logins within 5 minutes  -> lock + critical alert
    - USB removed within 60s of insertion         -> lock + critical alert
      (someone plugged a stick, copied fast, yanked it)
    """

    FAIL_LIMIT = 3
    FAIL_WINDOW = 300      # seconds
    GRAB_WINDOW = 60       # usb removed within N s of connect

    def __init__(self, config, alerts=None, logger=None):
        self.config = config
        self.logger = logger or print
        self.store = get_store(config)
        self.alerts = alerts
        cfg = config.section("panic")
        self.enabled = cfg.get("enabled", True)
        self.lock_on_grab = cfg.get("lock_on_usb_grab", True)
        self.lock_on_bruteforce = cfg.get("lock_on_bruteforce", True)
        self._fails = []
        self._usb_connected_at = {}
        self._lock = threading.Lock()
        self.idle = IdleLocker(config, alerts=alerts, logger=logger)

    # ---- dashboard login failures (called from webapp) ----

    def register_login_fail(self):
        if not self.enabled or not self.lock_on_bruteforce:
            return
        now = time.monotonic()
        with self._lock:
            self._fails = [t for t in self._fails if now - t < self.FAIL_WINDOW]
            self._fails.append(now)
            n = len(self._fails)
        self.logger(f"[panic] login fail #{n}/{self.FAIL_LIMIT}")
        if n >= self.FAIL_LIMIT:
            with self._lock:
                self._fails.clear()
            self._fire("BRUTE FORCE LOCKDOWN",
                       f"{n} failed dashboard logins in {self.FAIL_WINDOW // 60} min")

    # ---- usb grab detection (called from usbdisk) ----

    def usb_connected(self, mount):
        self._usb_connected_at[mount.upper()] = time.monotonic()

    def usb_removed(self, mount):
        key = mount.upper()
        t0 = self._usb_connected_at.pop(key, None)
        if not self.enabled or not self.lock_on_grab or t0 is None:
            return
        held = time.monotonic() - t0
        if held <= self.GRAB_WINDOW:
            self._fire("USB GRAB-AND-RUN",
                       f"{mount} removed after only {int(held)}s - possible data theft")

    def _fire(self, title, why):
        ok = lock_workstation()
        self.logger(f"[panic] {title}: {why} | lock={'OK' if ok else 'FAILED'}")
        self.store.insert_cam_event("panic", title.lower(), why) if hasattr(self.store, "insert_cam_event") else None
        if not self.alerts:
            return
        msg = (
            f"\U0001f6a8 PANIC: {title}\u200f\n"
            f"reason: {why}\n"
            f"action: {'PC LOCKED' if ok else 'LOCK FAILED'}\n"
            f"time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        event = {"src_host": "local", "src_port": -1, "dst_port": -1, "local_time": "", "ts": ""}
        self.alerts.send(event, "panic:lock", "critical", msg)

    def start(self):
        self.idle.start()

    def stop(self):
        self.idle.stop()