import ctypes
import threading
import time
from datetime import datetime

from .config import get_store


class TheftAlarm:
    """Detect laptop theft via unexpected power-source change.

    Polls GetSystemPowerStatus every 2s. When AC power is removed
    while the system has been idle for >idle_seconds → CRITICAL
    alert + auto-lock. Catches someone grabbing the plugged-in
    laptop and running with it.
    """

    def __init__(self, config, alerts=None, logger=None):
        self.config = config
        self.logger = logger or print
        self.store = get_store(config)
        self.alerts = alerts
        cfg = config.section("theft")
        self.enabled = cfg.get("enabled", True)
        self.idle_seconds = float(cfg.get("idle_before", 120))
        self.poll = float(cfg.get("poll_seconds", 2))
        self._stop = threading.Event()

    @staticmethod
    def _get_power_status():
        """Return (ac_line, battery_pct, is_charging)."""
        try:
            class SYSTEM_POWER_STATUS(ctypes.Structure):
                _fields_ = [
                    ("ACLineStatus", ctypes.c_byte),
                    ("BatteryFlag", ctypes.c_byte),
                    ("BatteryLifePercent", ctypes.c_byte),
                    ("Reserved1", ctypes.c_byte),
                    ("BatteryLifeTime", ctypes.c_uint32),
                    ("BatteryFullLifeTime", ctypes.c_uint32),
                ]
            st = SYSTEM_POWER_STATUS()
            ctypes.windll.kernel32.GetSystemPowerStatus(ctypes.byref(st))
            return st.ACLineStatus, st.BatteryLifePercent, st.BatteryFlag & 0x8
        except Exception:
            return 1, 0, False

    @staticmethod
    def _idle_seconds():
        class LASTINPUTINFO(ctypes.Structure):
            _fields_ = [("cbSize", ctypes.c_uint), ("dwTime", ctypes.c_uint)]
        lii = LASTINPUTINFO()
        lii.cbSize = ctypes.sizeof(LASTINPUTINFO)
        ctypes.windll.user32.GetLastInputInfo(ctypes.byref(lii))
        return (ctypes.windll.kernel32.GetTickCount() - lii.dwTime) / 1000.0

    def _run(self):
        prev_ac = 1
        while not self._stop.is_set():
            time.sleep(self.poll)
            try:
                ac, pct, charging = self._get_power_status()
                if prev_ac == 1 and ac == 0:  # just unplugged
                    idle = self._idle_seconds()
                    if idle >= self.idle_seconds:
                        self._fire(f"unplugged after {int(idle)}s idle (battery {pct}%)")
                        from .panic import lock_workstation
                        lock_workstation()
                prev_ac = ac
            except Exception as exc:
                self.logger(f"[theft] error: {exc}")

    def _fire(self, why):
        self.logger(f"[theft] \U0001f6a8 {why}")
        self.store.insert_event(
            time.strftime("%Y-%m-%d %H:%M:%S"),
            "theft", "local", -1, -1, "theft:alarm", "critical", {"detail": why}
        )
        if not self.alerts:
            return
        msg = (
            f"\U0001f6a8 THEFT ALARM\n"
            f"reason: {why}\n"
            f"time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        event = {"src_host": "local", "src_port": -1, "dst_port": -1, "local_time": "", "ts": ""}
        self.alerts.send(event, "theft:alarm", "critical", msg)

    def start(self):
        if not self.enabled:
            return
        threading.Thread(target=self._run, daemon=True).start()
        self.logger("[theft] theft alarm monitoring")

    def stop(self):
        self._stop.set()
