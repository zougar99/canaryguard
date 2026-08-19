# CanaryGuard 🛡️

OpenCanary honeypot + attack detection stack for Windows & Linux. Built on top of
[OpenCanary](https://github.com/thinkst/opencanary), it adds a live dashboard,
Telegram alerts, local protection modules and an embedded honeytoken protocol.

> ⚠️ **Security note:** copy `config.example.json` → `config.json` and fill in your
> **own** Telegram bot token / chat id. Never commit the real `config.json` (it is
> git-ignored on purpose).

---

## 🧩 What it does

| Module | What it detects | Ports / hooks |
|---|---|---|
| **OpenCanary honeypot** | fake SMTP, MQTT, LDAP, Modbus, DNS, PostgreSQL, Memcached, SSH, HTTP... | 15+ ports |
| **Ingest** | reads OpenCanary logs into SQLite | `ingest.py` |
| **Alerts** | Telegram / Discord / Slack / email notifications | `alerts.py` |
| **Dashboard** | live web UI: events, creds, sessions, keystrokes, files, secrets, cleanup | `127.0.0.1:8080` |
| **Session monitor** | Windows logon/logoff/failed logins (Security log) | needs admin |
| **Folder watchdog** | file create/modify/delete in user folders | `protect.py` |
| **Keylogger** | local keystroke capture + sensitive keyword alerts | `keylogger.py` |
| **Secret scanner** | scans file contents for tokens/keys/passwords | `secretscanner.py` |
| **Embedded honeytokens** | hidden tokens in normal-looking files (PNG/TXT/PDF) | `embedtokens.py` |
| **Decoys** | decoy credentials / files + beacon callbacks | `decoys.py` |

---

## 🚀 Quick start

```bash
# 1. install dependencies
pip install -e .

# 2. configure (fill in YOUR token / chat id / server ip)
cp config.example.json config.json

# 3. start the honeypot (OpenCanary) and CanaryGuard
#    (on Linux: adjust paths + folders to /home/...)
python main.py
```

Open the dashboard at `http://127.0.0.1:8080`.

On Windows you can register background startup via `setup-background.ps1`
(run as Administrator) — it creates ONLOGON tasks for both services.

---

## 🔑 Embedded honeytoken protocol

Files that look 100% normal but carry a hidden token + beacon:

| File | Where the secret is hidden |
|---|---|
| `photo.png` | LSB steganography in the pixels + EXIF metadata |
| `notes.txt` | zero-width characters (invisible line) |
| `report.pdf` | hidden stream + PDF metadata |

When the file is opened/read on the machine (atime scanner), or the beacon URL is
followed, a critical alert fires. You can verify any file is yours with the
`extract()` function in `embedtokens.py`.

A GUI helper to create custom honeytokens:

```bash
python honeytoken_builder.py     # or open-honeytoken-builder.ps1 (Windows)
```

---

## 🗂️ Project layout

```
canaryguard/
├── main.py                 # entry point, wires all modules
├── config.example.json     # template (no secrets!)
├── canaryguard/
│   ├── ingest.py           # OpenCanary log -> SQLite
│   ├── logstore.py         # SQLite schema + queries
│   ├── alerts.py           # Telegram/Discord/Slack/email
│   ├── webapp.py           # Flask dashboard + APIs
│   ├── decoys.py           # decoy files + beacons
│   ├── embedtokens.py      # embedded honeytoken protocol
│   ├── secretscanner.py    # file content secret detection
│   ├── keylogger.py        # local keystrokes (Windows)
│   ├── sessions.py         # Windows logon monitor
│   ├── protect.py          # folder watchdog + cleanup
│   └── config.py
├── templates/index.html    # dashboard UI
└── static/                 # dashboard assets
```

---

## 🔒 Privacy & security

- `config.json`, `*.db`, logs and decoys are **git-ignored** — they stay local.
- The Telegram bot token lives only in your local `config.json`.
- All captured data (keystrokes, creds, sessions) is stored locally in SQLite.

> This is a **defensive/honeypot** tool. Use it only on systems you own, and
> never plant real credentials as decoys.