"""Set or reset the CanaryGuard dashboard admin password.

The dashboard is single-user by design: the one admin account has full access
(Overview, Events, Actions — lock/panic/screenshot/IP-block, Manage monitors,
all API endpoints). This tool bootstraps or resets that password instead of
hand-editing config.json.

    python -m canaryguard.setup_admin                 # interactive prompt
    python -m canaryguard.setup_admin --generate       # random password, printed once
    python -m canaryguard.setup_admin --password PASS  # explicit password
    python -m canaryguard.setup_admin --username n     # default: admin
    python -m canaryguard.setup_admin --config PATH    # default: $CANARYGUARD_HOME/config.json if it exists, else <repo>/config.json
"""

import argparse
import getpass
import json
import os
import secrets
import shutil
import string
import sys

MIN_LEN = 12
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def resolve_config_path(explicit=None):
    if explicit:
        return explicit
    home = os.environ.get("CANARYGUARD_HOME")
    if home:
        cfg = os.path.join(home, "config.json")
        if os.path.exists(cfg):
            return cfg
    return os.path.join(REPO_ROOT, "config.json")


def generate_password(length=20):
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_=+"
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.isupper() for c in pwd) and any(c.islower() for c in pwd)
                and any(c.isdigit() for c in pwd)):
            return pwd


def update_config(path, username, password):
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    dash = data.setdefault("dashboard", {})
    dash["username"] = username
    dash["password"] = password
    dash.setdefault("secret_key", secrets.token_hex(32))
    backup = path + ".bak"
    if not os.path.exists(backup):
        try:
            shutil.copy2(path, backup)
        except OSError:
            pass
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    return data


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default=None, help="path to config.json (default: $CANARYGUARD_HOME or repo root)")
    ap.add_argument("--username", default=None, help="admin username (default: keep existing or 'admin')")
    ap.add_argument("--password", default=None, help="explicit password (visible in shell history — prefer --generate or interactive)")
    ap.add_argument("--generate", action="store_true", help="generate a strong random password and print it once")
    ap.add_argument("--force", action="store_true", help="allow passwords shorter than 12 characters")
    args = ap.parse_args(argv)

    path = resolve_config_path(args.config)
    if not os.path.exists(path):
        example = os.path.join(REPO_ROOT, "config.example.json")
        if os.path.exists(example):
            try:
                shutil.copy2(example, path)
                print(f"No config found — created {path} from config.example.json. Edit it before deploying.")
            except OSError as exc:
                print(f"Config not found at {path} and could not be created: {exc}", file=sys.stderr)
                return 2
        else:
            print(f"Config not found: {path}", file=sys.stderr)
            return 2

    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    existing_user = (data.get("dashboard") or {}).get("username")
    if args.username:
        username = args.username
    elif existing_user:
        username = existing_user
    elif args.generate or args.password:
        username = "admin"   # non-interactive: no prompt
    else:
        username = input("Admin username [admin]: ").strip() or "admin"

    if args.generate:
        password = generate_password()
        generated = True
    elif args.password:
        password, generated = args.password, False
    else:
        password = getpass.getpass(f"New password for {username} (min {MIN_LEN} chars): ")
        if password != getpass.getpass("Repeat password: "):
            print("Passwords do not match.", file=sys.stderr)
            return 2
        generated = False

    if len(password) < MIN_LEN and not args.force:
        print(f"Refusing password shorter than {MIN_LEN} chars (use --force to override).", file=sys.stderr)
        return 2

    update_config(path, username, password)
    print(f"Updated {path} (backup at {path}.bak)")
    print(f"Admin username : {username}")
    if generated:
        print(f"Admin password : {password}   <- shown once, store it in a password manager NOW")
    else:
        print("Admin password : (as entered)")
    print("Restart the dashboard / service for the change to take effect.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
