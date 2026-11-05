import math
import os
import threading
import time
from collections import Counter, deque
from datetime import datetime

from .config import get_store

_COMMON_EXTS = {
    "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "txt", "rtf", "odt",
    "jpg", "jpeg", "png", "gif", "bmp", "mp4", "mkv", "mp3", "wav",
    "zip", "rar", "7z", "tar", "gz", "csv", "json", "xml", "py", "js",
    "html", "css", "md", "db", "sqlite", "exe", "dll", "msi", "iso",
}


def file_entropy(path, sample_bytes=65536):
    """Shannon entropy of a file sample (bits/byte, 0..8). None if unreadable."""
    try:
        with open(path, "rb") as fh:
            data = fh.read(sample_bytes)
    except Exception:
        return None
    if len(data) < 512:
        return None  # too small to judge — skip tiny files
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


import re as _re
_ADAPTER_RE = _re.compile(r'^[A-Za-z0-9 _\-]{1,64}$')

def _safe_adapter(name):
    """Adapter names come from config and are interpolated into shell commands — whitelist them."""
    name = str(name or '').strip()
    return name if _ADAPTER_RE.match(name) else None


class RansomwareTripwire:
    """Detect mass file modification typical of ransomware encryption.

    Fed events from the folder watchdog. Detection layers:
      1. velocity:   >threshold files created/modified in <window seconds
      2. entropy:    >=entropy_trigger files reading as random (~8 bits/byte)
      3. ext shift:  >=ext_ratio of modified files share one non-standard ext
    Any of them fires a CRITICAL alert.
    """

    def __init__(self, config, alerts=None, logger=None):
        self.config = config
        self.logger = logger or print
        self.store = get_store(config)
        self.alerts = alerts
        cfg = config.section("ransomware")
        self.threshold = int(cfg.get("threshold", 40))
        self.window = float(cfg.get("window_seconds", 60))
        self.kill_net = cfg.get("kill_network", False)
        self.adapter = _safe_adapter(cfg.get("network_adapter", "Wi-Fi"))
        if cfg.get("network_adapter") and not self.adapter:
            print("[ransomware] network_adapter failed validation — network kill disabled")
        self.entropy_trigger = int(cfg.get("entropy_trigger", 8))
        self.entropy_threshold = float(cfg.get("entropy_threshold", 7.5))
        self.ext_ratio = float(cfg.get("ext_ratio", 0.6))
        self._events = {}  # folder -> deque of (ts, entropy_or_None, ext)
        self._lock = threading.Lock()

    def record(self, folder, path=""):
        now = time.monotonic()
        key = os.path.normpath(folder).lower()
        ext = ""
        if path:
            _, ext = os.path.splitext(path)
            ext = ext.lower().lstrip(".")
        entropy = file_entropy(path) if path else None
        with self._lock:
            evs = self._events.setdefault(key, deque())
            while evs and now - evs[0][0] >= self.window:
                evs.popleft()
            evs.append((now, entropy, ext))
            self._evaluate(key, evs)

    # ---- detection layers ----

    def _evaluate(self, folder, evs):
        count = len(evs)
        if count >= self.threshold:
            self._events.pop(folder, None)
            self._fire(folder, f"{count} files modified in {int(self.window)}s (velocity)", count)
            return
        entropies = [e for _, e, _ in evs if e is not None]
        high_entropy = sum(1 for e in entropies if e >= self.entropy_threshold)
        if high_entropy >= self.entropy_trigger:
            self._events.pop(folder, None)
            self._fire(folder, f"{high_entropy} files read as encrypted (entropy>={self.entropy_threshold})", high_entropy)
            return
        exts = [ext for _, _, ext in evs if ext]
        if len(exts) >= 10:
            top_ext, top_n = Counter(exts).most_common(1)[0]
            if (top_n / len(exts)) >= self.ext_ratio and top_ext not in _COMMON_EXTS:
                self._events.pop(folder, None)
                self._fire(folder, f"{top_n}/{len(exts)} files now share suspicious extension '.{top_ext}'", top_n)

    def _fire(self, folder, reason, count):
        self.store.insert_event(
            time.strftime("%Y-%m-%d %H:%M:%S"),
            "ransomware", "local", -1, -1,
            "ransomware:detected", "critical",
            {"detail": f"ransomware pattern in {folder}: {reason}"},
        )
        self.logger(f"\U0001f6a8 [ransomware] {reason} in {folder}!")
        if self.kill_net:
            self._kill_network()
        if not self.alerts:
            return
        event = {"src_host": "local", "src_port": -1, "dst_port": -1, "local_time": "", "ts": ""}
        self.alerts.send(event, "ransomware:detected", "critical",
            f"\U0001f6a8 RANSOMWARE PATTERN\n"
            f"folder: {folder}\n"
            f"reason: {reason}\n"
            f"network: {'KILLED' if self.kill_net else 'monitoring only'}\n"
            f"time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )

    def _kill_network(self):
        if not self.adapter:
            self.logger("[ransomware] network kill skipped — invalid adapter name in config")
            return
        try:
            os.system(f'netsh interface set interface "{self.adapter}" disable')
            self.logger(f"[ransomware] network killed ({self.adapter})")
        except Exception as exc:
            self.logger(f"[ransomware] net kill failed: {exc}")
