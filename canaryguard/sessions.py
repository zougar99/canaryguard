import json
import os
import threading
import time
from datetime import datetime

from .config import get_store

# Event IDs of interest (Windows Security log)
LOGON_SUCCESS = 4624
LOGON_FAILED = 4625
LOGOFF = 4634
SESSION_UNLOCK = 4801

LOGON_TYPE_NAMES = {
    2: "interactive (local)",
    3: "network (share)",
    4: "batch",
    5: "service",
    7: "unlock",
    8: "network clear text",
    9: "new credentials",
    10: "RDP (remote interactive)",
    11: "cached interactive",
}

STATE_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "session_state.json")


class SessionMonitor:
    """Watch the Windows Security event log for logon/logoff/session events.

    Reports who logged on (username), how (logon type, e.g. RDP) and from
    which source IP, so a remote intruder can be identified.  Requires the
    'Audit logon events' policy to be enabled (Security log).
    """

    def __init__(self, config, alerts=None, logger=None, poll=10.0):
        self.config = config
        self.logger = logger or print
        self.store = get_store(config)
        self.alerts = alerts
        self.poll = poll
        self._stop = threading.Event()
        self._thread = None
        self._last_record = self._load_state()

    # ---------- state ----------

    def _load_state(self):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as fh:
                return int(json.load(fh).get("last_record", 0))
        except Exception:
            return 0

    def _save_state(self):
        try:
            with open(STATE_FILE, "w", encoding="utf-8") as fh:
                json.dump({"last_record": self._last_record}, fh)
        except Exception:
            pass

    # ---------- event log reading ----------

    def _read_log(self):
        import win32evtlog

        handle = win32evtlog.OpenEventLog(None, "Security")
        try:
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(handle, flags, 0)
            # ReadEventLog returns in reverse chronological order (newest first)
            for ev in reversed(events):
                yield ev
        finally:
            win32evtlog.CloseEventLog(handle)

    def _check_access(self):
        """Return True if the Security log is readable (requires admin)."""
        import win32evtlog

        try:
            handle = win32evtlog.OpenEventLog(None, "Security")
            win32evtlog.CloseEventLog(handle)
            return True
        except Exception:
            return False

    @staticmethod
    def _extract(ev, event_id):
        inserts = list(ev.StringInserts or [])
        if event_id == LOGON_SUCCESS:
            # 4624: [5]=TargetUserName [6]=TargetDomainName [8]=LogonType
            #       [18]=SourceNetworkAddress [19]=SourcePort
            username = inserts[5] if len(inserts) > 5 else ""
            domain = inserts[6] if len(inserts) > 6 else ""
            logon_type = int(inserts[8]) if len(inserts) > 8 and inserts[8].isdigit() else 0
            src_ip = inserts[18] if len(inserts) > 18 else ""
            src_port = inserts[19] if len(inserts) > 19 else ""
            return username, domain, logon_type, src_ip, src_port
        if event_id == LOGON_FAILED:
            # 4625: [5]=TargetUserName [6]=TargetDomainName [10]=LogonType
            #       [19]=SourceNetworkAddress [20]=SourcePort
            username = inserts[5] if len(inserts) > 5 else ""
            domain = inserts[6] if len(inserts) > 6 else ""
            logon_type = int(inserts[10]) if len(inserts) > 10 and inserts[10].isdigit() else 0
            src_ip = inserts[19] if len(inserts) > 19 else ""
            src_port = inserts[20] if len(inserts) > 20 else ""
            return username, domain, logon_type, src_ip, src_port
        if event_id in (LOGOFF, SESSION_UNLOCK):
            username = inserts[1] if len(inserts) > 1 else ""
            return username, "", 0, "", ""
        return "", "", 0, "", ""

    def _handle_event(self, ev):
        event_id = ev.EventID & 0xFFFF
        if event_id not in (LOGON_SUCCESS, LOGON_FAILED, LOGOFF, SESSION_UNLOCK):
            return
        username, domain, logon_type, src_ip, src_port = self._extract(ev, event_id)
        if not username or username in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "DWM-1", "-", ""):
            return
        username = username.replace("$", "")
        if not username:
            return

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ltype_name = LOGON_TYPE_NAMES.get(logon_type, f"type {logon_type}")

        if event_id == LOGON_SUCCESS:
            if src_ip in ("", "-", "127.0.0.1", "::1") and logon_type in (2, 7, 11):
                return  # normal local logon, ignore by default
            status = "success"
            details = f"logon type={ltype_name}"
            severity = "high" if logon_type in (10, 8) and src_ip and src_ip not in ("-", "127.0.0.1", "::1") else "medium"
            subject = f"LOGON ({ltype_name}) user={username}"
        elif event_id == LOGON_FAILED:
            status = "failed"
            details = f"logon type={ltype_name}"
            severity = "medium"
            subject = f"FAILED LOGON user={username}"
        elif event_id == LOGOFF:
            status = "logoff"
            details = "session ended"
            severity = "info"
            subject = f"LOGOFF user={username}"
        else:
            status = "unlock"
            details = "session unlocked"
            severity = "info"
            subject = f"SESSION UNLOCK user={username}"

        src_ip = src_ip if src_ip and src_ip not in ("-", "::1") else ""
        raw = {
            "event_id": event_id,
            "username": username,
            "domain": domain,
            "logon_type": logon_type,
            "src_ip": src_ip,
            "src_port": src_port,
            "time": now,
        }
        self.store.insert_session(username, logon_type, src_ip, status, details, raw)
        self.logger(f"[sessions] {subject} src={src_ip or 'local'} ({ltype_name})")
        if status == "failed" and src_ip and hasattr(self, 'ipblock') and self.ipblock:
            self.ipblock.register_fail(src_ip)

        if self.alerts and severity in ("high", "medium"):
            msg = (
                f"{subject}\n"
                f"user: {username}@{domain or '?'}\n"
                f"how: {ltype_name}\n"
                f"from: {src_ip or 'local'}\n"
                f"time: {now}"
            )
            event = {
                "src_host": src_ip,
                "src_port": int(src_port) if src_port and src_port.isdigit() else -1,
                "dst_port": -1,
                "local_time": now,
                "ts": now,
            }
            self.alerts.send(event, f"session:{username}", severity, msg)

    # ---------- loop ----------

    def _run(self):
        time.sleep(self.poll)
        if not self._check_access():
            self.logger("[sessions] WARNING: cannot read Security log (need to run CanaryGuard as Administrator)")
            self._no_access = True
        else:
            self._no_access = False
        while not self._stop.is_set():
            if self._no_access:
                self._stop.wait(self.poll * 6)
                continue
            try:
                newest = self._last_record
                for ev in self._read_log():
                    rec = ev.RecordNumber
                    if rec > newest:
                        newest = rec
                    if self._last_record and rec <= self._last_record:
                        continue
                    self._handle_event(ev)
                if newest > self._last_record:
                    self._last_record = newest
                    self._save_state()
            except Exception as exc:
                self.logger(f"[sessions] error: {exc}")
            self._stop.wait(self.poll)

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self.logger(f"[sessions] monitoring Security log")

    def stop(self):
        self._stop.set()
        self._save_state()