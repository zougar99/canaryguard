import os
import subprocess
import threading
import time
from datetime import datetime

from .config import get_store

_BASE = r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"


def _deny_all(kind):
    """Set every app under ConsentStore\\<kind> to Deny (camera / microphone)."""
    try:
        import winreg
        root = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                              rf"{_BASE}\{kind}", 0, winreg.KEY_SET_VALUE)
        with root:
            winreg.SetValueEx(root, "Value", 0, winreg.REG_SZ, "Deny")
        # per-app subkeys too
        rk = winreg.OpenKey(winreg.HKEY_CURRENT_USER, rf"{_BASE}\{kind}")
        with rk:
            i = 0
            while True:
                try:
                    sub = winreg.EnumKey(rk, i)
                    i += 1
                    if sub == "NonPackaged":
                        continue
                    try:
                        sk = winreg.OpenKey(
                            winreg.HKEY_CURRENT_USER,
                            rf"{_BASE}\{kind}\\{sub}", 0, winreg.KEY_SET_VALUE)
                        with sk:
                            winreg.SetValueEx(sk, "Value", 0, winreg.REG_SZ, "Deny")
                    except OSError:
                        pass
                except OSError:
                    break
        return True
    except Exception:
        return False


def _allow_all(kind):
    try:
        import winreg
        root = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                              rf"{_BASE}\{kind}", 0, winreg.KEY_SET_VALUE)
        with root:
            winreg.SetValueEx(root, "Value", 0, winreg.REG_SZ, "Allow")
        return True
    except Exception:
        return False


import re as _re
_ADAPTER_RE = _re.compile(r'^[A-Za-z0-9 _\-]{1,64}$')

def _safe_adapter(name):
    """Adapter names come from config and are interpolated into shell commands — whitelist them."""
    name = str(name or '').strip()
    return name if _ADAPTER_RE.match(name) else None


class FortressMode:
    """One-button lockdown for when you leave the room.

    engage():  deny webcam + microphone (registry), optional Wi-Fi kill,
               send CRITICAL alert, optionally lock.
    disengage(): restore webcam/mic permissions (+ Wi-Fi), alert.

    Engaged state survives config/result and is checked by /fortress status.
    """

    def __init__(self, config, alerts=None, logger=None):
        self.config = config
        self.logger = logger or print
        self.store = get_store(config)
        self.alerts = alerts
        cfg = config.section("fortress")
        self.enabled = cfg.get("enabled", True)
        self.kill_wifi = bool(cfg.get("kill_wifi", False))
        self.lock_pc = bool(cfg.get("lock_pc", True))
        self.adapter = _safe_adapter(cfg.get("network_adapter", "Wi-Fi"))
        if cfg.get("network_adapter") and not self.adapter:
            print("[fortress] network_adapter failed validation — network kill disabled")
        self.engaged = False
        self._time = None
        self._tstate = {}   # adapter state before engage
        self._lock = threading.Lock()

    # ---- core actions ----

    def engage(self, reason="manual"):
        with self._lock:
            if self.engaged:
                return {"ok": False, "error": "already engaged"}
            cam = _deny_all("webcam")
            mic = _deny_all("microphone")
            wifi = None
            if self.kill_wifi and self.adapter and os.name == "nt":
                try:
                    state = subprocess.run(
                        ["netsh", "interface", "show", "interface", f"name={self.adapter}"],
                        capture_output=True, text=True, timeout=10).stdout
                    self._tstate[self.adapter] = state
                    r = os.system(f'netsh interface set interface "{self.adapter}" disable')
                    wifi = r == 0
                except Exception:
                    wifi = False
            if self.lock_pc:
                try:
                    subprocess.Popen(["rundll32.exe", "user32.dll,LockWorkStation"])
                except Exception:
                    pass
            self.engaged = True
            self._time = time.strftime("%Y-%m-%d %H:%M:%S")
        self.store.insert_event(
            time.strftime("%Y-%m-%d %H:%M:%S"),
            "fortress", "local", -1, -1, "panic:lock", "high",
            {"detail": f"fortress engaged ({reason}) cam={cam} mic={mic} wifi={wifi}"},
        )
        self.logger(f"[fortress] 🔒 ENGAGED (cam={cam} mic={mic} wifi={wifi})")
        if self.alerts:
            event = {"src_host": "local", "src_port": "-", "dst_port": "-",
                     "local_time": self._time, "ts": ""}
            self.alerts.send(
                event, "panic:lock", "high",
                f"\U0001f3f0 FORTRESS MODE ENGAGED\n"
                f"webcam+microphone: DENIED\n"
                f"wi-fi: {'KILLED' if wifi else 'untouched'}\n"
                f"reason: {reason}\n"
                f"time: {self._time}",
            )
        return {"ok": True, "cam": cam, "mic": mic, "wifi": wifi}

    def disengage(self, reason="manual"):
        with self._lock:
            if not self.engaged:
                return {"ok": False, "error": "not engaged"}
            cam = _allow_all("webcam")
            mic = _allow_all("microphone")
            wifi = True
            if self.kill_wifi and self.adapter in getattr(self, "_tstate", {}):
                r = os.system(f'netsh interface set interface "{self.adapter}" enable')
                wifi = r == 0
                self._tstate.pop(self.adapter, None)
            self.engaged = False
            self._time = time.strftime("%Y-%m-%d %H:%M:%S")
        self.store.insert_event(
            time.strftime("%Y-%m-%d %H:%M:%S"),
            "fortress", "local", -1, -1, "system:start", "low",
            {"detail": f"fortress disengaged ({reason})"},
        )
        self.logger(f"[fortress] ✅ disengaged")
        if self.alerts:
            event = {"src_host": "local", "src_port": "-", "dst_port": "-",
                     "local_time": self._time, "ts": ""}
            self.alerts.send(
                event, "system:start", "low",
                f"\U0001f513 FORTRESS MODE OFF\n"
                f"webcam/mic: restored\n"
                f"time: {self._time}",
            )
        return {"ok": True}

    def status(self):
        return {
            "engaged": self.engaged,
            "since": self._time,
            "kill_wifi": self.kill_wifi,
        }

    def start(self):
        self.logger(f"[fortress] ready (kill_wifi={self.kill_wifi})")

    def stop(self):
        pass
