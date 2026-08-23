import sys
import time

from canaryguard.config import Config
from canaryguard.decoys import DecoyAccessScanner, DecoyManager, DecoyWatcher
from canaryguard.embedtokens import EmbedAccessScanner, EmbedTokenManager
from canaryguard.ingest import Ingestor
from canaryguard.procs import ProcessMonitor
from canaryguard.protect import Cleanup, FolderWatchdog
from canaryguard.secretscanner import SecretScanner
from canaryguard.usbdisk import USBDiskMonitor
from canaryguard.webapp import DashboardServer

BASE = r"C:\Users\werlist99\canaryguard"
IS_WINDOWS = sys.platform.startswith("win")

if IS_WINDOWS:
    from canaryguard.keylogger import KeyLogger
    from canaryguard.sessions import SessionMonitor


def main():
    config = Config.load()
    ing = Ingestor(config)
    ing.start()

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
        watcher.start()
        scanner.start()

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
    um = USBDiskMonitor(config, alerts=ing.alerts)
    if config.get("usb_monitor", "enabled", default=True):
        um.start()
    secscan = SecretScanner(config, alerts=ing.alerts)
    if config.get("protect", "folder_monitor", default=True):
        fw = FolderWatchdog(config, alerts=ing.alerts, secrets=secscan)
        fw.start()

    if config.get("dashboard", "auto_start", default=True):
        dash = DashboardServer(config, decoys=decoys, cleanup=Cleanup(config), sessions=sesmon, keystrokes=kl, secrets=secscan, embeds=embeds)
        dash.run()

    print("[canaryguard] running. Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[canaryguard] stopping...")
        watcher.stop()
        scanner.stop()
        pm.stop()
        um.stop()
        if sesmon:
            sesmon.stop()
        if kl:
            kl.stop()
        ing.stop()


if __name__ == "__main__":
    main()