#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# CanaryGuard - Raspberry Pi / Linux server deployment
#
# Runs the beacon receiver + OpenCanary honeypot 24/7 on a small always-on
# box, so alerts keep arriving even when your Windows PC is turned off.
#
#   SSH into the Pi, then:
#     bash deploy-pi.sh
#
# It installs: python3 + pip, OpenCanary, CanaryGuard (this repo), a systemd
# service, and configures the beacon_host to your DDNS domain.
# -----------------------------------------------------------------------------
set -euo pipefail

DOMAIN="${1:?usage: bash deploy-pi.sh <your-ddns-domain-or-ip> [port]}"
PORT="${2:-8080}"
APP_DIR="/opt/canaryguard"
LOG_DIR="/opt/canaryguard/logs"

echo "=== CanaryGuard Pi deploy ==="
echo "  beacon host: $DOMAIN"
echo "  dashboard port: $PORT"
echo "  install dir : $APP_DIR"
echo ""

# --- 1. system packages ------------------------------------------------------
echo "[1/6] installing system packages..."
sudo apt-get update -y
sudo apt-get install -y python3 python3-venv python3-pip git curl nginx \
    python3-openssl libssl-dev libffi-dev

# --- 2. OpenCanary -----------------------------------------------------------
echo "[2/6] installing OpenCanary..."
sudo pip3 install --break-system-packages opencanary 2>/dev/null \
    || sudo pip3 install opencanary
sudo cp "$(command -v opencanary.tac)" /opt/ 2>/dev/null || true
sudo mkdir -p /var/log/opencanary

# --- 3. CanaryGuard repo -----------------------------------------------------
echo "[3/6] cloning CanaryGuard..."
sudo mkdir -p "$APP_DIR"
if [ ! -d "$APP_DIR/.git" ]; then
    sudo git clone https://github.com/zougar99/canaryguard.git "$APP_DIR"
fi
sudo mkdir -p "$LOG_DIR"
sudo chown -R "$USER" "$APP_DIR"

# --- 4. Python deps ----------------------------------------------------------
echo "[4/6] installing Python dependencies..."
python3 -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/pip" install --upgrade pip
"$APP_DIR/.venv/bin/pip" install -e "$APP_DIR"
"$APP_DIR/.venv/bin/pip" install watchdog

# --- 5. config ---------------------------------------------------------------
echo "[5/6] writing config.json..."
if [ ! -f "$APP_DIR/config.json" ]; then
    cp "$APP_DIR/config.example.json" "$APP_DIR/config.json"
fi

python3 - "$APP_DIR/config.json" "$DOMAIN" "$PORT" <<'PY'
import json, sys
path, domain, port = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path) as f:
    cfg = json.load(f)
cfg.setdefault("dashboard", {})["host"] = "0.0.0.0"
cfg["dashboard"]["port"] = int(port)
cfg.setdefault("decoys", {})["beacon_host"] = domain
cfg.setdefault("opencanary", {})["log_file"] = "/var/log/opencanary/opencanary.log"
cfg.setdefault("opencanary", {})["db_file"] = os.path.join(os.path.dirname(path), "canaryguard.db")
cfg.setdefault("protect", {}).setdefault("folders", [])[:] = ["/home/%s" % os.environ.get("USER", "pi")]
with open(path, "w") as f:
    json.dump(cfg, f, indent=4)
print("config updated")
PY

# --- 6. systemd service ------------------------------------------------------
echo "[6/6] installing systemd service..."
sudo tee /etc/systemd/system/canaryguard.service >/dev/null <<EOF
[Unit]
Description=CanaryGuard honeypot + beacon receiver
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$APP_DIR
ExecStart=$APP_DIR/.venv/bin/python $APP_DIR/main.py
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable canaryguard
sudo systemctl restart canaryguard

echo ""
echo "=== DONE ==="
echo "  Dashboard : http://$DOMAIN:$PORT  (login with config.json credentials)"
echo "  Beacons   : http://$DOMAIN:$PORT/t/<token>"
echo "  Logs      : journalctl -u canaryguard -f"
echo "  IMPORTANT : forward port $PORT (TCP) on your router to this Pi's LAN IP"
echo ""
echo "  The Windows PC's beacons now point here, so you get Telegram alerts"
echo "  even while the PC is switched off."