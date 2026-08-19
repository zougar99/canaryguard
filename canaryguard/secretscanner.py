import os
import re
import threading
import zlib
from datetime import datetime

from .config import get_store

# Built-in secret patterns: name -> (regex, severity)
DEFAULT_PATTERNS = [
    ("aws_access_key", r"\bAKIA[0-9A-Z]{16}\b", "high"),
    ("aws_secret", r"(?i)\bsecret\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?", "high"),
    ("github_token", r"\bgh[pousr]_[A-Za-z0-9]{30,}\b", "critical"),
    ("github_pat", r"\bgithub_pat_[A-Za-z0-9_]{20,}\b", "critical"),
    ("openai_key", r"\bsk-[A-Za-z0-9]{20,60}\b", "critical"),
    ("google_api", r"\bAIza[0-9A-Za-z\-_]{35}\b", "critical"),
    ("slack_token", r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b", "critical"),
    ("stripe_key", r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b", "critical"),
    ("jwt_token", r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b", "high"),
    ("private_key", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", "critical"),
    ("telegram_bot", r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b", "critical"),
    ("generic_password", r"(?i)(password|passwd|pwd|passphrase|secret|api[_-]?key)\s*[=:]\s*['\"][^'\"]{6,}['\"]", "high"),
    ("plain_password", r"(?i)\b(?:password|passwd|pwd)\s*=\s*[A-Za-z0-9_\-@#$%^&*!.]{6,}", "high"),
]

TEXT_EXT = {
    ".txt", ".md", ".log", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
    ".py", ".js", ".ts", ".jsx", ".tsx", ".sh", ".bat", ".cmd", ".ps1", ".vbs",
    ".java", ".c", ".cpp", ".h", ".go", ".rs", ".rb", ".php", ".sql", ".xml", ".html",
    ".csv", ".env", ".properties", ".xml", ".yml", ".gitconfig", ".npmrc",
}
BINARY_EXT = {".pdf", ".docx", ".doc", ".xlsx", ".zip", ".7z", ".rar", ".tar", ".gz"}
# do not scan binaries we can't meaningfully parse
SKIP_EXT = {".exe", ".dll", ".jpg", ".jpeg", ".png", ".gif", ".mp4", ".mp3", ".wav", ".pyc", ".ico", ".lnk"}


class SecretScanner:
    """Scan file contents for tokens / keys / passwords.

    Reads newly-created or modified text files (plus a best-effort PDF
    extractor) and looks for known secret patterns or user-defined
    watchstrings.  Hits are stored and alerted.
    """

    def __init__(self, config, alerts=None, logger=None):
        self.config = config
        self.logger = logger or print
        self.store = get_store(config)
        self.alerts = alerts
        self.max_kb = int(config.get("secrets", "max_file_kb", default=512))
        self.watchstrings = [s.lower() for s in config.get("secrets", "watch_strings", default=[])]
        patterns = list(DEFAULT_PATTERNS)
        for p in config.get("secrets", "extra_patterns", default=[]):
            if isinstance(p, dict) and p.get("name") and p.get("pattern"):
                patterns.append((p["name"], p["pattern"], p.get("severity", "high")))
        self.patterns = [(name, re.compile(pat), sev) for name, pat, sev in patterns]
        self._lock = threading.Lock()
        self._reported = {}  # (path, kind, value) -> ts, to avoid repeats

    # ---------- content extraction ----------

    def _read_text(self, path):
        ext = os.path.splitext(path)[1].lower()
        if ext in SKIP_EXT or ext in BINARY_EXT and ext != ".pdf":
            return None
        try:
            size = os.path.getsize(path)
            if size > self.max_kb * 1024:
                self.logger(f"[secrets] {os.path.basename(path)} too big ({size} bytes), skipping content scan")
                return None
            with open(path, "rb") as fh:
                raw = fh.read()
        except OSError as exc:
            self.logger(f"[secrets] read failed {path}: {exc}")
            return None
        if not raw:
            return None
        if ext == ".pdf":
            return self._extract_pdf(raw)
        # try utf-8 first, fall back to latin-1 for binary-ish files
        for enc in ("utf-8", "utf-16", "latin-1"):
            try:
                return raw.decode(enc)
            except (UnicodeDecodeError, ValueError):
                continue
        return raw.decode("latin-1", errors="replace")

    def _extract_pdf(self, raw):
        """Best-effort PDF text extraction: get text objects + inflate streams."""
        chunks = []
        for m in re.finditer(rb"\(([^()\\]{4,})\)", raw):
            try:
                chunks.append(m.group(1).decode("latin-1"))
            except Exception:
                pass
        # inflate FlateDecode streams which hold most PDF text
        for m in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", raw, re.S):
            data = m.group(1)
            try:
                chunks.append(zlib.decompress(data).decode("latin-1"))
            except Exception:
                try:
                    chunks.append(zlib.decompress(data, -15).decode("latin-1"))
                except Exception:
                    pass
        return "\n".join(chunks)

    # ---------- scanning ----------

    def _scan_text(self, text, path):
        hits = []
        lower = text.lower()
        for ws in self.watchstrings:
            if ws in lower:
                hits.append(("watchstring", ws, "user-defined watchstring"))
        for name, rx, sev in self.patterns:
            for m in rx.finditer(text):
                value = m.group(0)
                if len(value) > 200:
                    value = value[:200] + "..."
                hits.append((name, value, sev))
        return hits

    def scan_file(self, path):
        """Scan a single file. Returns list of (kind, value, severity)."""
        text = self._read_text(path)
        if not text:
            return []
        hits = []
        for kind, value, sev in self._scan_text(text, path):
            key = (path, kind, value)
            with self._lock:
                if key in self._reported:
                    continue
                self._reported[key] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            hits.append((kind, value, sev))
        return hits

    def report(self, path, hits):
        """Store and alert for found secrets."""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for kind, value, sev in hits:
            self.store.insert_secret_hit(path, kind, value, f"severity={sev}")
            self.logger(f"[secrets] {kind.upper()} in {path}: {value}")
            if self.alerts:
                msg = (
                    f"SECRET FOUND ({kind})\n"
                    f"path: {path}\n"
                    f"value: `{value}`\n"
                    f"time: {now}"
                )
                event = {"src_host": "", "src_port": -1, "dst_port": -1, "local_time": now, "ts": now}
                sev_level = sev if sev in ("low", "medium", "high", "critical") else "high"
                self.alerts.send(event, "secret:found", sev_level, msg)