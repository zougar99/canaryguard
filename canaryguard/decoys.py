import os
import random
import secrets
import string
import threading
import time
from datetime import datetime

from .config import get_store

DEFAULT_FOLDER = os.path.join(os.path.expanduser("~"), "CanaryDecoys")


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def new_token_id(kind):
    return f"{kind}-{secrets.token_hex(6)}"


def beacon_url(config, token_id):
    host = config.get("decoys", "beacon_host", default="127.0.0.1")
    port = int(config.get("dashboard", "port", default=8080))
    return f"http://{host}:{port}/t/{token_id}"


class DecoyManager:
    """Generate decoy files, monitor the decoy folder and handle beacons."""

    def __init__(self, config, alerts=None, logger=None):
        self.config = config
        self.logger = logger or print
        self.store = get_store(config)
        self.alerts = alerts
        self.folder = config.get("decoys", "folder", default=DEFAULT_FOLDER)
        self.beacon_host = config.get("decoys", "beacon_host", default="127.0.0.1")
        self._cooldown = {}

    # ---------- trip handling ----------

    def trip(self, token_id, kind, label, src_info="", raw=None):
        if not token_id:
            return
        if self.store.token_is_tripped(token_id) and token_id.startswith("decoy"):
            # one-shot tokens: only alert once, but still record repeat visits
            self.store.insert_token_trip(token_id, kind, label, src_info, raw)
            return

        key = f"{kind}:{token_id}"
        now = time.monotonic()
        last = self._cooldown.get(key)
        if last is not None and now - last < int(self.config.get("decoys", "cooldown_seconds", default=60)):
            return
        self._cooldown[key] = now

        self.store.insert_token_trip(token_id, kind, label, src_info, raw)
        if self.alerts:
            event = {
                "src_host": "",
                "src_port": -1,
                "dst_port": -1,
                "local_time": _now(),
                "ts": _now(),
            }
            msg = (
                f"DECOY TRIPPED ({kind}): {label}\n"
                f"src: {src_info or 'local'}\n"
                f"token: {token_id}"
            )
            self.alerts.send(event, f"decoy:{token_id}", "critical", msg)
        self.logger(f"[decoys] TRIPPED {kind} {token_id} label={label} src={src_info}")

    # ---------- generation ----------

    def generate(self, kinds=None):
        os.makedirs(self.folder, exist_ok=True)
        kinds = kinds or ["txt", "csv", "pdf", "bat", "ini", "sql", "wallet", "2fa"]
        created = []
        for kind in kinds:
            fn = getattr(self, f"_make_{kind}", None)
            if not fn:
                continue
            p = fn()
            created.append(p)
        self.logger(f"[decoys] generated {len(created)} decoys in {self.folder}")
        return created

    def _new_cred(self):
        pwd = "decoy-" + secrets.token_hex(4)
        return "admin", pwd

    def _register(self, kind, label, path, username=None, password=None):
        token_id = new_token_id(kind)
        beacon = beacon_url(self.config, token_id)
        self.store.register_decoy(token_id, kind, label, path, beacon, username, password)
        return token_id, beacon

    def _make_txt(self):
        user, pwd = self._new_cred()
        token_id, beacon = self._register("decoy_txt", "passwords.txt (credentials)", os.path.join(self.folder, "passwords.txt"), user, pwd)
        users = ["root", "admin", "administrator", "oracle", "postgres"]
        pws = ["toor", "admin1", "P@ssw0rd", "123456", "letmein", "password1"]
        lines = [
            "### DO NOT SHARE - LOCAL PASSWORDS BACKUP ###",
            f"token: {token_id}",
            "host        user            password",
        ]
        for u in users:
            lines.append(f"10.0.0.{random.randint(2, 30)}   {u:<14} {random.choice(pws)}")
        lines.append("")
        lines.append("MAIN SERVER:")
        lines.append(f"    login : {user}")
        lines.append(f"    pass  : {pwd}")
        lines.append("")
        lines.append(f"online backup: {beacon}")
        with open(os.path.join(self.folder, "passwords.txt"), "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        return os.path.join(self.folder, "passwords.txt")

    def _make_csv(self):
        token_id, beacon = self._register("decoy_csv", "payroll_2026.csv (financial)", os.path.join(self.folder, "payroll_2026.csv"))
        headers = ["employee_id", "name", "salary", "iban"]
        rows = []
        for i in range(12):
            rows.append(f"{1000+i},Employee {chr(65+i)},{(random.randint(35,95))}000,MA6400{''.join(random.choices(string.digits,k=14))}")
        body = "\n".join([",".join(headers)] + rows + [f"export,trigger,{beacon},N/A"])
        with open(os.path.join(self.folder, "payroll_2026.csv"), "w", encoding="utf-8") as fh:
            fh.write(body)
        return os.path.join(self.folder, "payroll_2026.csv")

    def _make_pdf(self):
        user, pwd = self._new_cred()
        token_id, beacon = self._register("decoy_pdf", "server_credentials.pdf (PDF)", os.path.join(self.folder, "server_credentials.pdf"), user, pwd)
        text = (
            "SERVER CREDENTIALS - RESTRICTED\n\n"
            f"MAIN SERVER:\n"
            f"  login : {user}\n"
            f"  pass  : {pwd}\n\n"
            f"Backup login page: {beacon}\n"
            f"token: {token_id}\n"
        )
        self._write_pdf(os.path.join(self.folder, "server_credentials.pdf"), text)
        return os.path.join(self.folder, "server_credentials.pdf")

    def _write_pdf(self, path, text):
        text = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        content = f"BT /F1 12 Tf 50 750 Td 15 TL {text} Tj ET"
        objects = []
        objects.append("<< /Type /Catalog /Pages 2 0 R >>")
        objects.append("<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
        objects.append("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
                       "/Resources << /Font << /F1 5 0 R >> >> >>")
        objects.append(f"<< /Length {len(content)} >>\nstream\n{content}\nendstream")
        objects.append("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

        out = ["%PDF-1.4"]
        offsets = []
        for i, obj in enumerate(objects, 1):
            offsets.append(len(out[-1]))
            out.append(f"{i} 0 obj\n{obj}\nendobj")
        xref_pos = len(b"\n".join(x.encode() for x in out)) + len(out) - 1
        xref = f"xref\n0 {len(objects)+1}\n0000000000 65535 f \n"
        for off in offsets:
            xref += f"{off:010d} 00000 n \n"
        trailer = f"trailer\n<< /Size {len(objects)+1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF"
        with open(path, "wb") as fh:
            fh.write(b"\n".join(x.encode() for x in out))
            fh.write(b"\n")
            fh.write(xref.encode())
            fh.write(trailer.encode())

    def _make_bat(self):
        token_id, beacon = self._register("decoy_app", "setup_tool.bat (application)", os.path.join(self.folder, "setup_tool.bat"))
        path = os.path.join(self.folder, "setup_tool.bat")
        code = (
            "@echo off\n"
            "title Setup Tool\n"
            "start /b \"\" cmd /c \"curl -s -o nul %s & timeout /t 2 /nobreak >nul & del /f /q \"%%~f0\"\" >nul 2>&1\n"
            "echo.\n"
            "echo [ERROR] Missing system component. Please contact administrator.\n"
            "echo.\n"
            "pause >nul\n"
        ) % beacon
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(code)
        return path

    def _make_ini(self):
        user, pwd = self._new_cred()
        token_id, beacon = self._register("decoy_ini", "web.config.ini (config)", os.path.join(self.folder, "web.config.ini"), user, pwd)
        path = os.path.join(self.folder, "web.config.ini")
        body = (
            "[database]\n"
            "host=10.0.0.1\n"
            f"username={user}\n"
            f"password={pwd}\n"
            "[backup]\n"
            f"url={beacon}\n"
            f"token={token_id}\n"
        )
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)
        return path

    def _make_sql(self):
        user, pwd = self._new_cred()
        token_id, beacon = self._register("decoy_sql", "users_export.sql (SQL dump)", os.path.join(self.folder, "users_export.sql"), user, pwd)
        path = os.path.join(self.folder, "users_export.sql")
        body = (
            "-- exported by admin 2026-08-19\n"
            "INSERT INTO users VALUES (1,'root','toor','10.0.0.1');\n"
            "INSERT INTO users VALUES (2,'admin','admin1','10.0.0.2');\n"
            f"INSERT INTO users VALUES (3,'{user}','{pwd}','10.0.0.3');\n"
            f"-- backup: {beacon}\n"
            f"-- token: {token_id}\n"
        )
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)
        return path


    def start_maintenance(self):
        """Keep decoys convincing: refresh timestamps daily so they look alive."""
        import threading

        def _loop():
            while True:
                time.sleep(21600)  # every 6h
                try:
                    now = time.time()
                    for name in os.listdir(self.folder):
                        p = os.path.join(self.folder, name)
                        if os.path.isfile(p):
                            os.utime(p, (now - random.randint(60, 86400),) * 2)
                    self.logger("[decoys] maintenance: refreshed timestamps")
                except Exception as exc:
                    self.logger(f"[decoys] maintenance error: {exc}")

        threading.Thread(target=_loop, daemon=True).start()
        self.logger("[decoys] maintenance loop started")

    def _make_wallet(self):
        """Fake Bitcoin core wallet.dat (binary blob with embedded beacon)."""
        token_id, beacon = self._register("decoy_wallet", "wallet.dat (crypto)", os.path.join(self.folder, "wallet.dat"))
        header = bytes.fromhex("00000001") + b"\x00" * 32
        marker = f"CANARYWALLET:{token_id}|{beacon}".encode()
        body = os.urandom(4096 - len(header) - len(marker))
        with open(os.path.join(self.folder, "wallet.dat"), "wb") as fh:
            fh.write(header + marker + body)
        return os.path.join(self.folder, "wallet.dat")

    def _make_2fa(self):
        token_id, beacon = self._register("decoy_2fa", "2fa_backup_codes.txt (auth)", os.path.join(self.folder, "2fa_backup_codes.txt"))
        lines = [
            "# Google Authenticator - BACKUP CODES",
            "# account: main@gmail.com",
            f"# generated: {time.strftime('%Y-%m-%d')}",
            f"# recovery endpoint: {beacon}",
        ]
        for _ in range(8):
            lines.append("".join(random.choices("ABCDEFGHJKLMNPQRSTUVWXYZ23456789", k=4)) + "-" +
                         "".join(random.choices("ABCDEFGHJKLMNPQRSTUVWXYZ23456789", k=4)))
        with open(os.path.join(self.folder, "2fa_backup_codes.txt"), "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        return os.path.join(self.folder, "2fa_backup_codes.txt")


class DecoyAccessScanner:
    """Best-effort read detector: watches last-access times of decoy files.

    On Windows/NTFS this depends on the system keeping 'last access time'
    updates enabled. Combined with the URL beacon (guaranteed) this gives
    broad coverage.
    """

    def __init__(self, config, manager: DecoyManager, logger=None, interval=5.0):
        self.config = config
        self.logger = logger or print
        self.manager = manager
        self.folder = config.get("decoys", "folder", default=DEFAULT_FOLDER)
        self.interval = interval
        self._baseline = {}
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        self._snapshot(baseline=True)
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _snapshot(self, baseline=False):
        snap = {}
        if os.path.isdir(self.folder):
            for root, _, files in os.walk(self.folder):
                for f in files:
                    p = os.path.join(root, f)
                    try:
                        st = os.stat(p)
                        snap[p] = (st.st_atime, st.st_mtime, st.st_size)
                    except OSError:
                        continue
        if baseline:
            self._baseline = snap
        return snap

    def _run(self):
        time.sleep(self.interval)
        while not self._stop.is_set():
            try:
                snap = self._snapshot()
                for path, (atime, mtime, size) in snap.items():
                    base = self._baseline.get(path)
                    label = os.path.basename(path)
                    if base is None:
                        self.manager.trip(f"decoy_folder:{label}", "created", f"new file appeared in decoy folder", src_info=f"created: {path}")
                        continue
                    b_atime, b_mtime, b_size = base
                    if mtime > b_mtime or size != b_size:
                        self.manager.trip(f"decoy_folder:{label}", "modified", f"file modified in decoy folder", src_info=f"modified: {path}")
                    elif atime > b_atime:
                        self.manager.trip(f"decoy_folder:{label}", "accessed", f"file READ in decoy folder", src_info=f"accessed: {path}")
                for path in set(self._baseline) - set(snap):
                    self.manager.trip(f"decoy_folder:{os.path.basename(path)}", "deleted", f"file REMOVED from decoy folder", src_info=f"deleted: {path}")
                self._baseline = snap
            except Exception as exc:
                self.logger(f"[decoys] scanner error: {exc}")
            self._stop.wait(self.interval)


class DecoyWatcher:
    """Watchdog-based folder monitor: any access to the decoy folder trips a token."""

    def __init__(self, config, manager: DecoyManager, logger=None):
        self.config = config
        self.logger = logger or print
        self.manager = manager
        self.folder = config.get("decoys", "folder", default=DEFAULT_FOLDER)
        self._observer = None

    def start(self):
        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler

            os.makedirs(self.folder, exist_ok=True)

            class Handler(FileSystemEventHandler):
                def on_any_event(self, event):
                    path = event.src_path.replace("\\", "/").lower()
                    if "canarydecoys" not in path:
                        return
                    label = os.path.basename(event.src_path)
                    self.manager.trip(
                        f"decoy_folder:{label}",
                        f"folder:{event.event_type}",
                        f"file access ({event.event_type}) in decoy folder",
                        src_info=f"{event.event_type}: {event.src_path}",
                        raw={"path": event.src_path, "event": event.event_type},
                    )

            self._observer = Observer()
            self._observer.schedule(Handler(), self.folder, recursive=True)
            self._observer.daemon = True
            self._observer.start()
            self.logger(f"[decoys] watching {self.folder}")
        except Exception as exc:
            self.logger(f"[decoys] watcher failed: {exc}")

    def stop(self):
        if self._observer:
            self._observer.stop()
            self._observer = None