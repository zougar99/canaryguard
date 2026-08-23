import json
import os
import sqlite3
import threading
from datetime import datetime, timezone


SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    utc_time TEXT,
    logtype INTEGER NOT NULL,
    src_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    category TEXT,
    severity TEXT,
    raw_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events (ts);
CREATE INDEX IF NOT EXISTS idx_events_src ON events (src_ip);
CREATE INDEX IF NOT EXISTS idx_events_logtype ON events (logtype);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    channel TEXT NOT NULL,
    subject TEXT,
    event_id INTEGER
);

CREATE TABLE IF NOT EXISTS creds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    src_ip TEXT,
    username TEXT,
    password TEXT,
    service TEXT,
    event_id INTEGER
);

CREATE TABLE IF NOT EXISTS ip_meta (
    ip TEXT PRIMARY KEY,
    country TEXT,
    region TEXT,
    city TEXT,
    org TEXT,
    updated TEXT
);

CREATE TABLE IF NOT EXISTS decoys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_id TEXT UNIQUE,
    kind TEXT,
    label TEXT,
    path TEXT,
    beacon TEXT,
    created TEXT,
    username TEXT,
    password TEXT
);

CREATE TABLE IF NOT EXISTS token_trips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    token_id TEXT NOT NULL,
    kind TEXT,
    label TEXT,
    src_info TEXT,
    raw_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_token_trips_id ON token_trips (token_id);

CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    username TEXT,
    logon_type INTEGER,
    source_ip TEXT,
    status TEXT,
    details TEXT,
    raw_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_ts ON sessions (ts);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions (username);
CREATE INDEX IF NOT EXISTS idx_sessions_ip ON sessions (source_ip);

CREATE TABLE IF NOT EXISTS keystrokes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    window TEXT,
    keys TEXT,
    raw_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_keystrokes_ts ON keystrokes (ts);

CREATE TABLE IF NOT EXISTS file_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    folder TEXT,
    path TEXT,
    action TEXT,
    details TEXT
);
CREATE INDEX IF NOT EXISTS idx_file_events_ts ON file_events (ts);
CREATE INDEX IF NOT EXISTS idx_file_events_path ON file_events (path);

CREATE TABLE IF NOT EXISTS secret_hits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    path TEXT,
    kind TEXT,
    value TEXT,
    details TEXT
);
CREATE INDEX IF NOT EXISTS idx_secret_hits_ts ON secret_hits (ts);
CREATE INDEX IF NOT EXISTS idx_secret_hits_path ON secret_hits (path);

CREATE TABLE IF NOT EXISTS process_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    event_type TEXT,
    name TEXT,
    pid INTEGER,
    path TEXT,
    username TEXT,
    details TEXT
);
CREATE INDEX IF NOT EXISTS idx_process_events_ts ON process_events (ts);
CREATE INDEX IF NOT EXISTS idx_process_events_name ON process_events (name);

CREATE TABLE IF NOT EXISTS usb_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    event_type TEXT,
    drive TEXT,
    details TEXT
);
CREATE INDEX IF NOT EXISTS idx_usb_events_ts ON usb_events (ts);

CREATE TABLE IF NOT EXISTS clipboard_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    preview TEXT,
    chars INTEGER,
    keyword TEXT
);
CREATE INDEX IF NOT EXISTS idx_clipboard_events_ts ON clipboard_events (ts);

CREATE TABLE IF NOT EXISTS net_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    name TEXT,
    pid INTEGER,
    remote TEXT,
    details TEXT
);
CREATE INDEX IF NOT EXISTS idx_net_events_ts ON net_events (ts);

CREATE TABLE IF NOT EXISTS held_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    category TEXT,
    severity TEXT,
    subject TEXT,
    extra TEXT
);

CREATE TABLE IF NOT EXISTS cam_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    kind TEXT,
    app TEXT,
    details TEXT
);
CREATE INDEX IF NOT EXISTS idx_cam_events_ts ON cam_events (ts);
"""


class LogStore:
    def __init__(self, db_file):
        self.db_file = db_file
        os.makedirs(os.path.dirname(db_file), exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_file, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._migrate()
        self._conn.commit()

    def _migrate(self):
        cols = {r[1] for r in self._conn.execute("PRAGMA table_info(decoys)")}
        if "username" not in cols:
            self._conn.execute("ALTER TABLE decoys ADD COLUMN username TEXT")
        if "password" not in cols:
            self._conn.execute("ALTER TABLE decoys ADD COLUMN password TEXT")

    def insert_event(self, ts, logtype, src_ip, src_port, dst_port, category, severity, raw):
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO events (ts, utc_time, logtype, src_ip, src_port, dst_port, category, severity, raw_json) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (ts, raw.get("utc_time", ""), logtype, src_ip, src_port, dst_port, category, severity, json.dumps(raw, ensure_ascii=False)),
            )
            self._conn.commit()
            return cur.lastrowid

    def insert_alert(self, channel, subject, event_id=None):
        with self._lock:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self._conn.execute("INSERT INTO alerts (ts, channel, subject, event_id) VALUES (?,?,?,?)", (ts, channel, subject, event_id))
            self._conn.commit()

    def insert_cred(self, src_ip, username, password, service, event_id):
        with self._lock:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self._conn.execute("INSERT INTO creds (ts, src_ip, username, password, service, event_id) VALUES (?,?,?,?,?,?)", (ts, src_ip, username, password, service, event_id))
            self._conn.commit()

    def upsert_ip_meta(self, ip, country, region, city, org):
        with self._lock:
            updated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            self._conn.execute(
                "INSERT INTO ip_meta (ip, country, region, city, org, updated) VALUES (?,?,?,?,?,?) "
                "ON CONFLICT(ip) DO UPDATE SET country=excluded.country, region=excluded.region, "
                "city=excluded.city, org=excluded.org, updated=excluded.updated",
                (ip, country, region, city, org, updated),
            )
            self._conn.commit()

    def ip_meta(self, ip):
        with self._lock:
            row = self._conn.execute("SELECT * FROM ip_meta WHERE ip=?", (ip,)).fetchone()
            return dict(row) if row else None

    def has_event(self, event_id):
        with self._lock:
            row = self._conn.execute("SELECT 1 FROM events WHERE id=?", (event_id,)).fetchone()
            return row is not None

    # ---- queries for the dashboard ----

    def recent_events(self, limit=50):
        with self._lock:
            rows = self._conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]

    def counts_by_category(self, hours=24):
        with self._lock:
            rows = self._conn.execute(
                "SELECT category, COUNT(*) AS n FROM events WHERE ts >= datetime('now', ?) GROUP BY category ORDER BY n DESC",
                (f"-{hours} hours",),
            ).fetchall()
            return [(r["category"], r["n"]) for r in rows]

    def counts_by_severity(self, hours=24):
        with self._lock:
            rows = self._conn.execute(
                "SELECT severity, COUNT(*) AS n FROM events WHERE ts >= datetime('now', ?) GROUP BY severity",
                (f"-{hours} hours",),
            ).fetchall()
            return [(r["severity"], r["n"]) for r in rows]

    def top_ips(self, limit=15, hours=24):
        with self._lock:
            rows = self._conn.execute(
                "SELECT src_ip, COUNT(*) AS n FROM events WHERE ts >= datetime('now', ?) AND src_ip IS NOT NULL GROUP BY src_ip ORDER BY n DESC LIMIT ?",
                (f"-{hours} hours", limit),
            ).fetchall()
            return [dict(r) for r in rows]

    def ip_history(self, src_ip, limit=30):
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM events WHERE src_ip=? ORDER BY id DESC LIMIT ?", (src_ip, limit)
            ).fetchall()
            return [dict(r) for r in rows]

    def creds_captured(self, limit=50):
        with self._lock:
            rows = self._conn.execute("SELECT * FROM creds ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]

    def timeline(self, hours=24):
        with self._lock:
            rows = self._conn.execute(
                "SELECT strftime('%Y-%m-%d %H:00', ts) AS hour, COUNT(*) AS n FROM events "
                "WHERE ts >= datetime('now', ?) GROUP BY hour ORDER BY hour",
                (f"-{hours} hours",),
            ).fetchall()
            return [(r["hour"], r["n"]) for r in rows]

    def geo_points(self, hours=24):
        with self._lock:
            rows = self._conn.execute(
                "SELECT e.src_ip, m.country, m.city, m.region, COUNT(*) AS n FROM events e "
                "LEFT JOIN ip_meta m ON e.src_ip = m.ip "
                "WHERE e.ts >= datetime('now', ?) AND e.src_ip IS NOT NULL "
                "GROUP BY e.src_ip",
                (f"-{hours} hours",),
            ).fetchall()
            return [dict(r) for r in rows]

    def total_events(self):
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()
            return row["n"]

    def total_creds(self):
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS n FROM creds").fetchone()
            return row["n"]

    def register_decoy(self, token_id, kind, label, path, beacon, username=None, password=None):
        with self._lock:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self._conn.execute(
                "INSERT OR IGNORE INTO decoys (token_id, kind, label, path, beacon, created, username, password) VALUES (?,?,?,?,?,?,?,?)",
                (token_id, kind, label, path, beacon, ts, username, password),
            )
            self._conn.commit()

    def decoy_creds(self):
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM decoys WHERE username IS NOT NULL AND password IS NOT NULL"
            ).fetchall()
            return [dict(r) for r in rows]

    def decoys(self):
        with self._lock:
            rows = self._conn.execute("SELECT * FROM decoys ORDER BY id").fetchall()
            return [dict(r) for r in rows]

    def token_is_tripped(self, token_id):
        with self._lock:
            row = self._conn.execute("SELECT 1 FROM token_trips WHERE token_id=?", (token_id,)).fetchone()
            return row is not None

    def insert_token_trip(self, token_id, kind, label, src_info, raw=None):
        with self._lock:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            import json as _json

            self._conn.execute(
                "INSERT INTO token_trips (ts, token_id, kind, label, src_info, raw_json) VALUES (?,?,?,?,?,?)",
                (ts, token_id, kind, label, src_info, _json.dumps(raw or {}, ensure_ascii=False)),
            )
            self._conn.commit()

    def token_trips(self, limit=100):
        with self._lock:
            rows = self._conn.execute("SELECT * FROM token_trips ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]

    def recent_token_trips(self, limit=20):
        with self._lock:
            rows = self._conn.execute("SELECT * FROM token_trips ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]

    def first_ts(self):
        with self._lock:
            row = self._conn.execute("SELECT MIN(ts) AS t FROM events").fetchone()
            return row["t"]

    # ---- sessions ----

    def insert_session(self, username, logon_type, source_ip, status, details, raw):
        with self._lock:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cur = self._conn.execute(
                "INSERT INTO sessions (ts, username, logon_type, source_ip, status, details, raw_json) "
                "VALUES (?,?,?,?,?,?,?)",
                (ts, username, logon_type, source_ip, status, details, json.dumps(raw, ensure_ascii=False)),
            )
            self._conn.commit()
            return cur.lastrowid

    def recent_sessions(self, limit=100):
        with self._lock:
            rows = self._conn.execute("SELECT * FROM sessions ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]

    def total_sessions(self):
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS n FROM sessions").fetchone()
            return row["n"]

    def failed_logins(self, hours=24):
        with self._lock:
            rows = self._conn.execute(
                "SELECT username, COUNT(*) AS n FROM sessions WHERE status='failed' "
                "AND ts >= datetime('now', ?) GROUP BY username ORDER BY n DESC",
                (f"-{hours} hours",),
            ).fetchall()
            return [(r["username"], r["n"]) for r in rows]

    # ---- keystrokes ----

    def insert_keystrokes(self, window, keys, raw=None):
        with self._lock:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self._conn.execute(
                "INSERT INTO keystrokes (ts, window, keys, raw_json) VALUES (?,?,?,?)",
                (ts, window, keys, json.dumps(raw or {}, ensure_ascii=False)),
            )
            self._conn.commit()

    def recent_keystrokes(self, limit=100):
        with self._lock:
            rows = self._conn.execute("SELECT * FROM keystrokes ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]

    def total_keystrokes(self):
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS n FROM keystrokes").fetchone()
            return row["n"]

    # ---- file events ----

    def insert_file_event(self, folder, path, action, details):
        with self._lock:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self._conn.execute(
                "INSERT INTO file_events (ts, folder, path, action, details) VALUES (?,?,?,?,?)",
                (ts, folder, path, action, details),
            )
            self._conn.commit()

    def recent_file_events(self, limit=100):
        with self._lock:
            rows = self._conn.execute("SELECT * FROM file_events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]

    def total_file_events(self):
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS n FROM file_events").fetchone()
            return row["n"]

    # ---- secret hits ----

    def insert_secret_hit(self, path, kind, value, details):
        with self._lock:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cur = self._conn.execute(
                "INSERT INTO secret_hits (ts, path, kind, value, details) VALUES (?,?,?,?,?)",
                (ts, path, kind, value, details),
            )
            self._conn.commit()
            return cur.lastrowid

    def recent_secret_hits(self, limit=100):
        with self._lock:
            rows = self._conn.execute("SELECT * FROM secret_hits ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]

    def total_secret_hits(self):
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS n FROM secret_hits").fetchone()
            return row["n"]

    # ---- process events ----

    def insert_process_event(self, event_type, name, pid, path, username, details):
        with self._lock:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cur = self._conn.execute(
                "INSERT INTO process_events (ts, event_type, name, pid, path, username, details) VALUES (?,?,?,?,?,?,?)",
                (ts, event_type, name, pid, path, username, details),
            )
            self._conn.commit()
            return cur.lastrowid

    def recent_process_events(self, limit=100):
        with self._lock:
            rows = self._conn.execute("SELECT * FROM process_events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]

    def total_process_events(self):
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS n FROM process_events").fetchone()
            return row["n"]

    # ---- drive/usb events ----

    def insert_usb_event(self, event_type, drive, details):
        with self._lock:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cur = self._conn.execute(
                "INSERT INTO usb_events (ts, event_type, drive, details) VALUES (?,?,?,?)",
                (ts, event_type, drive, details),
            )
            self._conn.commit()
            return cur.lastrowid

    def recent_usb_events(self, limit=100):
        with self._lock:
            rows = self._conn.execute("SELECT * FROM usb_events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]

    def total_usb_events(self):
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS n FROM usb_events").fetchone()
            return row["n"]

    # ---- clipboard ----

    def insert_clipboard_event(self, preview, chars, keyword):
        with self._lock:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cur = self._conn.execute(
                "INSERT INTO clipboard_events (ts, preview, chars, keyword) VALUES (?,?,?,?)",
                (ts, preview, chars, keyword),
            )
            self._conn.commit()
            return cur.lastrowid

    def recent_clipboard_events(self, limit=100):
        with self._lock:
            rows = self._conn.execute("SELECT * FROM clipboard_events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]

    def total_clipboard_events(self):
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS n FROM clipboard_events").fetchone()
            return row["n"]

    # ---- network ----

    def insert_net_event(self, name, pid, remote, details):
        with self._lock:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cur = self._conn.execute(
                "INSERT INTO net_events (ts, name, pid, remote, details) VALUES (?,?,?,?,?)",
                (ts, name, pid, remote, details),
            )
            self._conn.commit()
            return cur.lastrowid

    def recent_net_events(self, limit=100):
        with self._lock:
            rows = self._conn.execute("SELECT * FROM net_events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]

    def total_net_events(self):
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS n FROM net_events").fetchone()
            return row["n"]

    # ---- held (night-quiet) alerts ----

    def insert_held_alert(self, category, severity, subject, extra=""):
        with self._lock:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cur = self._conn.execute(
                "INSERT INTO held_alerts (ts, category, severity, subject, extra) VALUES (?,?,?,?,?)",
                (ts, category, severity, subject, extra),
            )
            self._conn.commit()
            return cur.lastrowid

    def drain_held_alerts(self):
        with self._lock:
            rows = self._conn.execute("SELECT * FROM held_alerts ORDER BY id").fetchall()
            if rows:
                self._conn.execute("DELETE FROM held_alerts")
                self._conn.commit()
            return [dict(r) for r in rows]

    # ---- camera/mic/panic ----

    def insert_cam_event(self, kind, app, details=""):
        with self._lock:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cur = self._conn.execute(
                "INSERT INTO cam_events (ts, kind, app, details) VALUES (?,?,?,?)",
                (ts, kind, app, details),
            )
            self._conn.commit()
            return cur.lastrowid

    def recent_cam_events(self, limit=100):
        with self._lock:
            rows = self._conn.execute("SELECT * FROM cam_events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]

    def total_cam_events(self):
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS n FROM cam_events").fetchone()
            return row["n"]

    def close(self):
        with self._lock:
            self._conn.close()