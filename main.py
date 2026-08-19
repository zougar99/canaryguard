import sys
import time

from canaryguard.config import Config
from canaryguard.decoys import DecoyAccessScanner, DecoyManager, DecoyWatcher
from canaryguard.embedtokens import EmbedAccessScanner, EmbedTokenManager
from canaryguard.ingest import Ingestor
from canaryguard.keylogger import KeyLogger
from canaryguard.protect import Cleanup, FolderWatchdog
from canaryguard.secretscanner import SecretScanner
from canaryguard.sessions import SessionMonitor
from canaryguard.webapp import DashboardServer

BASE = r"C:\Users\werlist99\canaryguard"


def main():
    config = Config.load()
    ing = Ingestor(config)
    ing.start()

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
    sesmon = SessionMonitor(config, alerts=ing.alerts)
    sesmon.start()
    secscan = SecretScanner(config, alerts=ing.alerts)
    if config.get("protect", "folder_monitor", default=True):
        fw = FolderWatchdog(config, alerts=ing.alerts, secrets=secscan)
        fw.start()
    kl = KeyLogger(config, alerts=ing.alerts)
    kl.start()

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
        sesmon.stop()
        kl.stop()
        ing.stop()


if __name__ == "__main__":
    main()