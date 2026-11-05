import threading
import sys
import time

# make console logging emoji/unicode-safe on legacy Windows codepages
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from canaryguard import control as ctl
from canaryguard.config import Config
from canaryguard.decoys import DecoyAccessScanner, DecoyManager, DecoyWatcher
from canaryguard.embedtokens import EmbedAccessScanner, EmbedTokenManager
from canaryguard.ingest import Ingestor
from canaryguard.netmon import NetworkMonitor
from canaryguard.procs import ProcessMonitor
from canaryguard.protect import Cleanup, FolderWatchdog
from canaryguard.secretscanner import SecretScanner
from canaryguard.tgbot import TelegramCommandBot as TGBot
from canaryguard.usbdisk import USBDiskMonitor
from canaryguard.webapp import DashboardServer

BASE = r"C:\Users\werlist99\canaryguard"
IS_WINDOWS = sys.platform.startswith("win")

if IS_WINDOWS:
    from canaryguard.browserwatch import BrowserCredsWatch
    from canaryguard.camwatch import CameraMicMonitor
    from canaryguard.clipboard import ClipboardMonitor
    from canaryguard.downloads import DownloadsSentinel
    from canaryguard.evidence import EvidenceBackup
    from canaryguard.ipblocker import IPBlocker
    from canaryguard.keylogger import KeyLogger
    from canaryguard.lannet import WiFiDeviceMonitor
    from canaryguard.panic import PanicManager
    from canaryguard.persist import PersistenceWatchdog
    from canaryguard.ransomware import RansomwareTripwire
    from canaryguard.sessions import SessionMonitor
    from canaryguard.staging import StagingDetector
    from canaryguard.theft import TheftAlarm


_INSTANCE_HANDLE = None


def _single_instance_guard():
    """Windows named mutex: only one CanaryGuard may run at a time.

    Werkzeug sets SO_REUSEADDR, which on Windows lets several processes bind
    the same port. Without this guard a repeated auto-revive piles up dozens
    of main.py instances that all write to the same SQLite DB, starve the CPU
    and make the watchdog think the dashboard is down again.
    """
    if not IS_WINDOWS:
        return None
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateMutexW.restype = wintypes.HANDLE
        kernel32.CreateMutexW.argtypes = (wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR)
        handle = kernel32.CreateMutexW(None, False, "Local\\CanaryGuardSingleInstance")
        if not handle:
            return None
        if ctypes.get_last_error() == 183:  # ERROR_ALREADY_EXISTS
            return False
        return handle
    except Exception as exc:
        print(f"[main] single-instance guard unavailable: {exc}")
        return None


class _RuntimeControl:
    """Pause / resume / stop / restart, driven by the dashboard or Telegram.

    Pause keeps the process and dashboard alive but stops every monitor.
    Stop writes the "stopped" flag (so the watchdog leaves it down) and shuts
    the process down. The always-on supervisor (cgctl.py) can start it again.
    """

    def __init__(self, monitors, alerts=None, logger=print):
        self.monitors = monitors or {}
        self.alerts = alerts
        self.logger = logger
        self.mode = "running"
        self.stop_event = threading.Event()

    def _notify(self, text):
        try:
            if self.alerts:
                self.alerts.send_raw(text)
        except Exception:
            pass

    def _each(self, action):
        ok, failed = 0, []
        for name, mon in self.monitors.items():
            if mon is None:
                continue
            try:
                getattr(mon, action)()
                ok += 1
            except Exception as exc:
                failed.append(f"{name}: {exc}")
        return ok, failed

    def _clear_flags(self):
        for mon in self.monitors.values():
            flag = getattr(mon, "_stop", None)
            if flag is not None:
                try:
                    flag.clear()
                except Exception:
                    pass

    def pause(self, reason=""):
        self.mode = "paused"
        ctl.write_state("paused", reason)
        ok, failed = self._each("stop")
        self.logger(f"[control] paused: {ok} monitors stopped, {len(failed)} failed")
        self._notify(f"\u23f8 <b>CanaryGuard PAUSED</b>\nreason: {reason or '-'}\n"
                     f"monitors stopped: {ok}\ndashboard stays online")
        return {"ok": ok, "failed": failed}

    def resume(self, reason=""):
        self.mode = "running"
        ctl.write_state("running", reason)
        self._clear_flags()
        ok, failed = self._each("start")
        self.logger(f"[control] resumed: {ok} monitors started, {len(failed)} failed")
        self._notify(f"\u25b6 <b>CanaryGuard RESUMED</b>\nreason: {reason or '-'}\n"
                     f"monitors started: {ok}")
        return {"ok": ok, "failed": failed}

    def shutdown(self, reason=""):
        self.mode = "stopped"
        ctl.set_stop_flag(True, reason)
        ctl.write_state("stopped", reason)
        self._notify(f"\u23f9 <b>CanaryGuard STOPPED</b>\nreason: {reason or '-'}\n"
                     f"send /start to bring it back")
        # give the HTTP response time to leave before the process exits
        threading.Timer(1.0, self.stop_event.set).start()

    def restart(self, reason=""):
        import subprocess

        self.mode = "restarting"
        ctl.set_stop_flag(False, reason)
        ctl.write_state("restarting", reason)
        self._notify(f"\U0001f504 <b>CanaryGuard RESTARTING</b>\nreason: {reason or '-'}")
        try:
            from canaryguard._winproc import detach

            detach(["cmd.exe", "/c",
                    "ping -n 4 127.0.0.1 >nul & schtasks /run /tn CanaryGuard"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as exc:
            self.logger(f"[control] restart spawn failed: {exc}")
        threading.Timer(1.2, self.stop_event.set).start()


def main():
    global _INSTANCE_HANDLE
    _INSTANCE_HANDLE = _single_instance_guard()
    if _INSTANCE_HANDLE is False:
        print("[main] another CanaryGuard instance is already running - exiting")
        return
    config = Config.load()
    ipb = None
    if IS_WINDOWS:
        ipb = IPBlocker(config)
        threading.Thread(target=ipb.cleanup_loop, daemon=True).start()
    ing = Ingestor(config, ipblock=ipb)
    ing.start()
    if ipb:
        ipb.alerts = ing.alerts

    if config.get("alerts", "notify_on_start", default=True):
        try:
            from datetime import datetime
            ing.alerts.send(
                {"src_host": "local", "src_port": -1, "dst_port": -1, "local_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
                "system:start",
                "medium",
                "CanaryGuard started. PC online, all sensors armed.",
            )
        except Exception as exc:
            print(f"[startup-notify] failed: {exc}")

    decoys = DecoyManager(config, alerts=ing.alerts)
    watcher = DecoyWatcher(config, decoys)
    scanner = DecoyAccessScanner(config, decoys)
    if config.get("decoys", "monitor_enabled", default=True):
        try:
            decoys.generate()
        except Exception as exc:
            print(f"[decoys] generate failed: {exc}")
        watcher.start()
        scanner.start()
        decoys.start_maintenance()

    # ---- embedded honeytoken protocol (hidden tokens in normal files) ----
    embeds = EmbedTokenManager(config, alerts=ing.alerts)
    if config.get("secrets", "embed_enabled", default=True):
        try:
            embeds.generate()
            escan = EmbedAccessScanner(config, embeds)
            escan.start()
        except Exception as exc:
            print(f"[embed] init failed: {exc}")

    # ---- local protection: sessions, folders, keylogger, secrets ----
    sesmon = None
    kl = None
    if IS_WINDOWS:
        sesmon = SessionMonitor(config, alerts=ing.alerts)
        sesmon.start()
        kl = KeyLogger(config, alerts=ing.alerts)
        kl.start()
    else:
        print("[main] non-Windows: keylogger & session monitor disabled")
    pm = ProcessMonitor(config, alerts=ing.alerts)
    if config.get("process_monitor", "enabled", default=True):
        pm.start()
    panic = None
    if IS_WINDOWS:
        panic = PanicManager(config, alerts=ing.alerts)
        ing.alerts._panic = panic
        if config.get("panic", "enabled", default=True):
            panic.start()
    um = USBDiskMonitor(config, alerts=ing.alerts, panic=panic)
    if config.get("usb_monitor", "enabled", default=True):
        um.start()
    nm = NetworkMonitor(config, alerts=ing.alerts)
    if config.get("netmon", "enabled", default=True):
        nm.start()
    cm = None
    if IS_WINDOWS:
        cm = ClipboardMonitor(config, alerts=ing.alerts)
        if config.get("clipboard_monitor", "enabled", default=True):
            cm.start()
    # ---- extra Windows monitors: lan, downloads, cam, staging, browser, persist, theft, evidence ----
    monitors: dict = {}
    randsom = None
    if IS_WINDOWS:
        def _safe(name, mon, section):
            try:
                if config.get(section, "enabled", default=True):
                    mon.start()
                    monitors[name] = mon
            except Exception as exc:
                print(f"[main] {name} failed: {exc}")
        _safe("lan", WiFiDeviceMonitor(config, alerts=ing.alerts), "lan_monitor")
        _safe("downloads", DownloadsSentinel(config, alerts=ing.alerts), "downloads_monitor")
        _safe("cam", CameraMicMonitor(config, alerts=ing.alerts), "cam_monitor")
        _safe("staging", StagingDetector(config, alerts=ing.alerts), "staging_monitor")
        _safe("browser", BrowserCredsWatch(config, alerts=ing.alerts), "browser_monitor")
        _safe("persist", PersistenceWatchdog(config, alerts=ing.alerts), "persist_monitor")
        _safe("theft", TheftAlarm(config, alerts=ing.alerts), "theft_monitor")
        _safe("evidence", EvidenceBackup(config, alerts=ing.alerts), "evidence_monitor")

    # ---- notification power-ups: night escalation, digest, telegram bot ----
    ing.alerts.start_background()
    try:
        from canaryguard.weekly import WeeklyRecap

        WeeklyRecap(config, alerts=ing.alerts).start()
    except Exception as exc:
        print(f"[main] weekly recap failed to start: {exc}")
    bot = TGBot(config, alerts=ing.alerts)
    bot.monitors = {"procs": pm, "usb": um, "net": nm}
    if cm:
        bot.monitors["clip"] = cm
    if sesmon:
        bot.monitors["sessions"] = sesmon
    if kl:
        bot.monitors["keys"] = kl
    bot.monitors["decoys"] = watcher
    if panic:
        bot.monitors["panic"] = panic.idle
    bot.monitors.update(monitors)
    # The always-on supervisor (cgctl.py) owns Telegram polling so that
    # /start still works while this service is stopped. Two pollers on one
    # bot token would fight over getUpdates (409 Conflict).
    bot_owner = str(config.get("telegram_bot", "owner", default="supervisor")).lower()
    if config.get("telegram_bot", "enabled", default=True) and bot_owner != "supervisor":
        bot.start()
    else:
        print("[bot] telegram polling owned by supervisor (cgctl.py)")
    secscan = SecretScanner(config, alerts=ing.alerts)
    fw = None
    if config.get("protect", "folder_monitor", default=True):
        if IS_WINDOWS and config.get("ransomware_monitor", "enabled", default=True):
            try:
                randsom = RansomwareTripwire(config, alerts=ing.alerts)
                print("[main] ransomware tripwire armed (fed by folder watchdog)")
            except Exception as exc:
                print(f"[main] ransomware failed: {exc}")
        fw = FolderWatchdog(config, alerts=ing.alerts, secrets=secscan, ransomware=randsom)
        fw.start()

    runtime_monitors = dict(bot.monitors)
    if fw is not None:
        runtime_monitors["protect"] = fw
    runtime_monitors["decoys_scan"] = scanner
    runtime = _RuntimeControl(runtime_monitors, alerts=ing.alerts)
    ctl.set_stop_flag(False, "service started")
    ctl.write_state("running", "service started")

    if config.get("dashboard", "auto_start", default=True):
        dash = DashboardServer(config, decoys=decoys, cleanup=Cleanup(config), sessions=sesmon, keystrokes=kl, secrets=secscan, embeds=embeds, alerts=ing.alerts, monitors=bot.monitors, ipblock=ipb, runtime=runtime)
        dash.run()

    print("[canaryguard] running. Ctrl+C to stop.")
    awake_stop = _start_keep_awake()
    try:
        while not runtime.stop_event.wait(1):
            pass
        print("[canaryguard] control requested shutdown")
    except KeyboardInterrupt:
        print("\n[canaryguard] stopping...")
        if awake_stop:
            awake_stop.set()
        watcher.stop()
        scanner.stop()
        bot.stop()
        pm.stop()
        um.stop()
        nm.stop()
        for extra, m in monitors.items():
            try:
                m.stop()
            except Exception:
                pass
        if panic:
            panic.stop()
        if cm:
            cm.stop()
        if sesmon:
            sesmon.stop()
        if kl:
            kl.stop()
        ing.stop()

    if runtime.mode != "restarting":
        ctl.write_state("stopped", "process exited")


def _start_keep_awake():
    """Hard-block Windows sleep / display-off while CanaryGuard runs."""
    if not IS_WINDOWS:
        return None
    try:
        import ctypes
        ES_CONTINUOUS = 0x80000000
        ES_SYSTEM_REQUIRED = 0x00000001
        ES_DISPLAY_REQUIRED = 0x00000002
        kernel32 = ctypes.windll.kernel32
        stop = threading.Event()

        def _pulse():
            while not stop.is_set():
                try:
                    kernel32.SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED)
                except Exception:
                    pass
                stop.wait(10)

        threading.Thread(target=_pulse, daemon=True).start()
        print("[keepawake] sleep + display-off blocked (ES_SYSTEM_REQUIRED|ES_DISPLAY_REQUIRED)")
        return stop
    except Exception as exc:
        print(f"[keepawake] unavailable: {exc}")
        return None


if __name__ == "__main__":
    main()