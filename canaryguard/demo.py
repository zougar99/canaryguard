"""Demo mode — generate a believable attack history and serve the dashboard.

Seeds a self-contained demo database (events, creds, GeoIP, incidents, token
trips, sessions, process + network activity) and optionally serves the
dashboard against it. Everything lands in <home>/demo_data/ by default —
never in your real database.

    python -m canaryguard.demo                 # seed + serve on 0.0.0.0:8090
    python -m canaryguard.demo --seed-only     # just seed
    python -m canaryguard.demo --port 8090

DEMO ONLY: the demo dashboard has NO AUTHENTICATION when no password is set.
Do not expose it beyond your machine/network.
"""

import argparse
import json
import os
import random
import sys
from datetime import datetime, timedelta

from .paths import BASE_DIR

DEMO_DIR = os.path.join(BASE_DIR, "demo_data")
DEMO_DB = os.path.join(DEMO_DIR, "demo.db")
DEMO_CFG = os.path.join(DEMO_DIR, "config.json")

_ATTACKERS = [
    # (ip, country, city, org, profile)
    ("185.220.14.17", "DE", "Frankfurt", "Tor Exit Node", "brute"),
    ("45.148.10.111", "RU", "Moscow", "Hostkey B.V.", "spray"),
    ("193.142.146.77", "CN", "Shanghai", "Chinanet", "recon"),
    ("103.75.190.25", "IN", "Mumbai", "Bharti Airtel", "exploit"),
    ("89.248.165.44", "NL", "Amsterdam", "Schlund+Partner", "fullchain"),
    ("41.141.30.199", "MA", "Casablanca", "Maroc Telecom", "opportunist"),
    ("177.234.40.98", "BR", "Sao Paulo", "Claro", "recon"),
    ("196.52.43.10", "FR", "Paris", "OVH SAS", "brute"),
    ("92.118.39.115", "US", "Ashburn", "Amazon AWS", "exploit"),
    ("222.186.21.9", "CN", "Beijing", "China Unicom", "spray"),
]

_RECON_PATHS = ["/", "/wp-admin/", "/.env", "/.git/config", "/phpmyadmin/", "/actuator/health", "/api/v1/status"]
_CREDS = [("admin", "admin"), ("root", "toor"), ("admin", "123456"), ("test", "test123"),
          ("oracle", "oracle"), ("postgres", "postgres"), ("administrator", "P@ssw0rd")]


def _ts(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def seed(home=DEMO_DIR, db_path=DEMO_DB, seed_value=42):
    from .logstore import LogStore

    random.seed(seed_value)
    os.makedirs(home, exist_ok=True)
    if os.path.exists(db_path):
        os.remove(db_path)
    store = LogStore(db_path)

    now = datetime.now()

    def add_event(dt, logtype, src_ip, src_port, dst_port, category, severity, raw):
        store.insert_event(_ts(dt), logtype, src_ip, src_port, dst_port, category, severity,
                           raw or {"logtype": logtype, "local_time": _ts(dt), "src_host": src_ip})

    # ---- 7 days of background noise + two attack waves ----
    for day_back in range(6, -1, -1):
        day = now - timedelta(days=day_back)
        is_wave = day_back in (2, 0)  # yesterday and today: attack waves
        for ip, country, city, org, profile in _ATTACKERS:
            base_count = random.randint(8, 30) if is_wave else random.randint(0, 6)
            for _ in range(base_count):
                t = day.replace(hour=random.randint(0, 23), minute=random.randint(0, 59),
                                second=random.randint(0, 59), microsecond=0)
                sport = random.randint(20000, 60000)
                if profile == "recon":
                    add_event(t, 5002, ip, sport, random.choice([22, 80, 443, 3306, 6379]),
                              "port_scan", "low", None)
                elif profile == "brute":
                    user, pw = random.choice(_CREDS)
                    add_event(t, 4002, ip, sport, 22, "brute_force", "critical",
                              {"logtype": 4002, "USERNAME": user, "PASSWORD": pw,
                               "local_time": _ts(t)})
                    if random.random() < 0.35:
                        store.insert_cred(ip, user, pw, "ssh", None)
                elif profile == "spray":
                    user = random.choice(["admin", "user", "test", "backup", f"user{random.randint(1,300)}"])
                    add_event(t, 8001, ip, sport, 3306, "database_attack", "high",
                              {"logtype": 8001, "USERNAME": user, "PASSWORD": "123456",
                               "local_time": _ts(t)})
                    if random.random() < 0.3:
                        store.insert_cred(ip, user, "123456", "mysql", None)
                elif profile == "exploit":
                    path = random.choice(_RECON_PATHS)
                    add_event(t, 3000, ip, sport, 80, "exploit_attempt" if "../" in path else "http_probe",
                              "high" if "../" in path else "low",
                              {"logtype": 3000, "PATH": path, "local_time": _ts(t)})
                elif profile == "fullchain":
                    # recon -> exploit -> credentials: one rich incident
                    stage = random.choice(["recon", "exploit", "brute"])
                    if stage == "recon":
                        add_event(t, 3002, ip, sport, 80, "recon", "low",
                                  {"logtype": 3002, "PATH": random.choice(_RECON_PATHS), "local_time": _ts(t)})
                    elif stage == "exploit":
                        add_event(t, 3001, ip, sport, 80, "web_login_attack", "high",
                                  {"logtype": 3001, "PATH": "/login", "local_time": _ts(t)})
                    else:
                        user, pw = random.choice(_CREDS)
                        add_event(t, 4002, ip, sport, 22, "brute_force", "critical",
                                  {"logtype": 4002, "USERNAME": user, "PASSWORD": pw,
                                   "local_time": _ts(t)})
                        store.insert_cred(ip, user, pw, "ssh", None)
                else:  # opportunist
                    add_event(t, 3000, ip, sport, 80, "http_probe", "low",
                              {"logtype": 3000, "PATH": "/", "local_time": _ts(t)})

    # ---- the "fullchain" attacker gets a guaranteed deep timeline ----
    chain_ip = "89.248.165.44"
    t0 = now - timedelta(hours=5)
    for i, (logtype, category, severity, path) in enumerate([
        (3002, "recon", "low", "/"),
        (3002, "recon", "low", "/robots.txt"),
        (3001, "web_login_attack", "high", "/login"),
        (8001, "database_attack", "high", None),
        (4002, "brute_force", "critical", None),
        (10001, "file_exfil_attempt", "medium", None),
    ]):
        t = t0 + timedelta(minutes=i * 7)
        raw = {"logtype": logtype, "local_time": _ts(t)}
        if path:
            raw["PATH"] = path
        if logtype in (4002, 8001):
            raw.update({"USERNAME": "root", "PASSWORD": "toor"})
        add_event(t, logtype, chain_ip, 51000 + i, {3002: 80, 3001: 80, 8001: 3306, 4002: 22, 10001: 69}[logtype],
                  category, severity, raw)
    store.insert_cred(chain_ip, "root", "toor", "ssh", None)

    # ---- sessions, processes, network ----
    for i in range(4):
        t = now - timedelta(hours=random.randint(1, 72))
        store.insert_session("werlist99", 2, random.choice(["", "", "203.0.113.44"]),
                             "failed" if i else "success",
                             "demo seed", {"logon_type": 2})
    for i, (name, user) in enumerate([("chrome.exe", "werlist99"), ("code.exe", "werlist99"),
                                      ("notepad.exe", "werlist99"), ("winword.exe", "werlist99"),
                                      ("powershell.exe", "werlist99")]):
        store.insert_process_event("started", name, 4000 + i, f"C:\\Demo\\{name}", user,
                                   f"started: {name} pid={4000 + i}")

    # ---- a periodic beacon from an internal host (A7 demo) ----
    beacon_remote = "45.148.10.111:443"
    t0 = now - timedelta(hours=12)
    for i in range(48):  # exactly every 15 minutes
        t = t0 + timedelta(minutes=15 * i)
        store.insert_net_event("svchost.exe", 1088, beacon_remote, "new outbound (demo)")

    # ---- token trips + feedback ----
    store.insert_token_trip("tok_backup", "url", "Fake backup archive", "src=89.248.165.44 (Amsterdam)", {})
    store.insert_token_trip("tok_admin", "credential", "Fake admin creds", "src=45.148.10.111 service=ssh", {})
    store.insert_feedback(1, "brute_force", "tp", "confirmed botnet")
    store.insert_feedback(2, "http_probe", "fp", "monitoring service")

    # ---- GeoIP rows ----
    for ip, country, city, org, _ in _ATTACKERS:
        store.upsert_ip_meta(ip, country, country, city, org)

    store.close()
    return db_path


def write_config(home=DEMO_DIR, db_path=DEMO_DB, port=8090):
    os.makedirs(home, exist_ok=True)
    cfg = {
        "opencanary": {"log_file": os.path.join(home, "opencanary.log"), "db_file": db_path},
        "alerts": {"enabled": False, "min_severity": "medium", "geoip": False,
                   "telegram": {"enabled": False}, "discord": {"enabled": False},
                   "slack": {"enabled": False}, "email": {"enabled": False}},
        "dashboard": {
            "host": "0.0.0.0",
            "port": port,
            "auto_start": True,
            "username": "admin",
            "password": "",
            "noauth_allow_remote": True,   # DEMO ONLY — anyone who can reach the port sees fake data
            "trusted_networks": [],
            "secret_key": "demo-mode-not-a-secret"
        },
        "ingest": {"poll_seconds": 2, "start_from_end": True},
        "telegram_bot": {"enabled": False, "owner": "supervisor"},
        "analytics": {"enabled": True},
        "retention": {"enabled": False},
        "threatintel": {"enabled": False, "feeds": []},
    }
    with open(os.path.join(home, "config.json"), "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=4)
    return os.path.join(home, "config.json")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Seed a demo CanaryGuard database and optionally serve the dashboard")
    parser.add_argument("--seed-only", action="store_true", help="only seed the database, do not serve")
    parser.add_argument("--port", type=int, default=8090)
    parser.add_argument("--home", default=DEMO_DIR)
    parser.add_argument("--db", default=DEMO_DB)
    parser.add_argument("--seed-value", type=int, default=42)
    args = parser.parse_args(argv)

    print("=" * 64)
    print(" CANARYGUARD DEMO MODE")
    print(" Seeding fake attack history — no real data is used or shown.")
    print("=" * 64)
    db = seed(home=args.home, db_path=args.db, seed_value=args.seed_value)
    cfg = write_config(home=args.home, db_path=db, port=args.port)
    print(f"[demo] seeded {db}")
    if args.seed_only:
        print("[demo] seed-only requested, exiting")
        return 0
    print("\n*** DEMO ONLY: dashboard has NO authentication and is reachable")
    print("*** from this network. Bind a demo port you trust. ***\n")
    from .config import Config
    from .webapp import DashboardServer

    config = Config.load(cfg)
    dash = DashboardServer(config, monitors={}, ipblock=None, runtime=None)
    print(f"[demo] dashboard on http://0.0.0.0:{args.port}  (Ctrl+C to stop)")
    dash.run(host="0.0.0.0", port=args.port)
    import time

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[demo] stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
