import re
from collections import defaultdict, deque
from datetime import datetime, timedelta

# logtype -> (category, severity)
LOG_TYPE_MAP = {
    2000: ("brute_force", "ftp", "high"),
    2001: ("brute_force", "ftp", "medium"),
    3000: ("http_probe", "http", "low"),
    3001: ("web_login_attack", "http", "high"),
    3002: ("recon", "http", "low"),
    3003: ("recon", "http", "low"),
    4000: ("recon", "ssh", "low"),
    4001: ("recon", "ssh", "low"),
    4002: ("brute_force", "ssh", "high"),
    5000: ("file_access", "smb", "medium"),
    5001: ("port_scan", "tcp", "low"),
    5002: ("port_scan", "tcp", "low"),
    5003: ("port_scan", "tcp", "low"),
    5004: ("port_scan", "tcp", "low"),
    5005: ("port_scan", "tcp", "low"),
    6001: ("brute_force", "telnet", "high"),
    6002: ("recon", "telnet", "low"),
    7001: ("web_login_attack", "http", "high"),
    8001: ("database_attack", "mysql", "high"),
    9001: ("database_attack", "mssql", "high"),
    9002: ("database_attack", "mssql", "high"),
    9003: ("database_attack", "mysql", "medium"),
    10001: ("file_exfil_attempt", "tftp", "medium"),
    11001: ("dos_attempt", "ntp", "high"),
    12001: ("recon", "vnc", "low"),
    13001: ("recon", "snmp", "low"),
    14001: ("recon", "rdp", "medium"),
    15001: ("voip_scan", "sip", "low"),
    16001: ("recon", "git", "low"),
    17001: ("database_attack", "redis", "high"),
    18001: ("recon", "tcpbanner", "low"),
    18002: ("recon", "tcpbanner", "low"),
    18003: ("recon", "tcpbanner", "medium"),
    18004: ("recon", "tcpbanner", "medium"),
    18005: ("recon", "tcpbanner", "medium"),
    19001: ("recon", "llmnr", "low"),
    20001: ("database_attack", "mongodb", "high"),
    21001: ("brute_force", "fakeapi", "high"),
    21002: ("shell_command", "fakeapi", "high"),
    22001: ("mail_scanner", "smtp", "medium"),
    22002: ("brute_force", "pop3", "high"),
    22003: ("brute_force", "imap", "high"),
    22004: ("database_attack", "postgresql", "high"),
    22005: ("api_probe", "elasticsearch", "medium"),
    22006: ("api_exploit_attempt", "docker", "high"),
    22007: ("api_probe", "kubernetes", "medium"),
    22008: ("camera_scan", "rtsp", "medium"),
    22009: ("ics_probe", "modbus", "high"),
    22010: ("database_attack", "memcached", "high"),
    22011: ("recon", "dns", "low"),
    22012: ("iot_probe", "mqtt", "medium"),
    22013: ("remote_access_probe", "teamviewer", "medium"),
    22014: ("directory_probe", "ldap", "medium"),
    22015: ("java_exploit_probe", "rmi", "high"),
}

SKIP_LOGTYPES = {1000, 1001, 1002, 1003, 1004, 1005, 1006}

CRED_FIELDS = ("username", "password")

PATH_SENSITIVE = re.compile(
    r"(admin|login|password|passwd|secret|backup|config|\.env|\.git|wp-|phpmyadmin|shell|cmd|exec|upload)", re.I
)
PATH_ATTACK = re.compile(r"(\.\./|\.\.\\|/etc/|passwd|/proc/|cmd|exec|\\x|%;|union|select|eval|../../)", re.I)


def extract_creds(logdata, service):
    """Pull username/password out of an event's logdata dict."""
    if not isinstance(logdata, dict):
        return None
    for key in ("username", "password"):
        if key in logdata:
            user = logdata.get("username", "")
            pwd = logdata.get("password", "")
            if user:
                return {"username": user, "password": pwd, "service": service}
    for key in ("USERNAME", "PASSWORD"):
        if key in logdata:
            user = logdata.get("USERNAME", "")
            pwd = logdata.get("PASSWORD", "")
            if user:
                return {"username": user, "password": pwd, "service": service}
    return None


def classify(event):
    """Map a parsed OpenCanary event to (category, service, severity, creds, honeytoken_hit)."""
    logtype = event.get("logtype")
    if logtype in SKIP_LOGTYPES:
        return None, None, None, None, None

    logdata = event.get("logdata", {})
    entry = LOG_TYPE_MAP.get(logtype)
    if entry is None:
        return "unknown", "unknown", "medium", None, None

    category, service, severity = entry
    creds = None
    honeytoken_hit = False

    if logtype in (2000, 2001, 4002, 6001, 8001, 9001, 9002, 20001, 21001, 22002, 22003):
        creds = extract_creds(logdata, service)
        if logtype in (6001, 4002, 8001) and creds is not None:
            severity = "critical"

    if logtype in (3000, 3001, 3002, 3003):
        path = str(logdata.get("PATH", ""))
        if PATH_ATTACK.search(path):
            category = "exploit_attempt"
            severity = "high"
        elif PATH_SENSITIVE.search(path):
            category = "sensitive_access"
            severity = "medium"

    return category, service, severity, creds, honeytoken_hit


class AttackProfiler:
    """In-memory behavioural analysis of source IPs (feature-based, pure Python)."""

    WINDOW = 300  # seconds

    def __init__(self):
        self._sources = {}

    def _bucket(self, ip):
        now = datetime.now()
        cutoff = now - timedelta(seconds=self.WINDOW)
        if ip not in self._sources:
            self._sources[ip] = {"events": deque(), "users": defaultdict(set)}
        prof = self._sources[ip]
        while prof["events"] and prof["events"][0][0] < cutoff:
            prof["events"].popleft()
        return prof

    def update(self, ip, category, username=None):
        if not ip:
            return {}
        prof = self._bucket(ip)
        prof["events"].append((datetime.now(), category))
        if username:
            prof["users"][category].add(username)

        events = prof["events"]
        total = len(events)
        brute = sum(1 for _, c in events if c == "brute_force")
        scan = sum(1 for _, c in events if c in ("port_scan", "recon"))
        unique_users = len(prof["users"].get("brute_force", set()))

        score = 0
        if brute >= 5:
            score += 40
        elif brute >= 3:
            score += 25
        if unique_users >= 5:
            score += 30  # credential stuffing
        elif unique_users >= 3:
            score += 15
        if scan >= 10:
            score += 20
        if total >= 50:
            score += 10

        if score >= 70:
            label = "aggressive attacker"
        elif score >= 40:
            label = "persistent attacker"
        elif score >= 20:
            label = "suspicious source"
        elif total > 0:
            label = "casual probe"
        else:
            label = ""

        return {
            "ip": ip,
            "events_5min": total,
            "brute_attempts_5min": brute,
            "scan_events_5min": scan,
            "unique_users_5min": unique_users,
            "score": score,
            "label": label,
        }