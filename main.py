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


def main():
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
    if config.get("telegram_bot", "enabled", default=True):
        bot.start()
    secscan = SecretScanner(config, alerts=ing.alerts)
    if config.get("protect", "folder_monitor", default=True):
        if IS_WINDOWS and config.get("ransomware_monitor", "enabled", default=True):
            try:
                randsom = RansomwareTripwire(config, alerts=ing.alerts)
                print("[main] ransomware tripwire armed (fed by folder watchdog)")
            except Exception as exc:
                print(f"[main] ransomware failed: {exc}")
        fw = FolderWatchdog(config, alerts=ing.alerts, secrets=secscan, ransomware=randsom)
        fw.start()

    if config.get("dashboard", "auto_start", default=True):
        dash = DashboardServer(config, decoys=decoys, cleanup=Cleanup(config), sessions=sesmon, keystrokes=kl, secrets=secscan, embeds=embeds, alerts=ing.alerts)
        dash.run()

    print("[canaryguard] running. Ctrl+C to stop.")
    awake_stop = _start_keep_awake()
    try:
        while True:
            time.sleep(1)
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