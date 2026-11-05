<p align="center">
  <img src="assets/logo.png" alt="CanaryGuard logo" width="132">
</p>

<h1 align="center">CanaryGuard</h1>

<p align="center">
  <b>Self-hosted honeypot + host intrusion detection + remote control for Windows and Linux.</b>
</p>

CanaryGuard sits on top of [OpenCanary](https://github.com/thinkst/opencanary) and turns a
single machine into a monitored decoy host: fake network services attract scanners, local
sensors watch the real host, everything is stored in SQLite, and every meaningful event can
reach your phone through Telegram, Discord, Slack, e-mail or a SIEM.

The whole stack can be paused, stopped, restarted or brought back from a Telegram group or
channel, even when the main service is completely down.

<p align="center">
  <sub>Logo and app icon live in <a href="assets/">assets/</a> · vector versions:
  <a href="assets/logo.svg">logo.svg</a> · <a href="assets/icon.svg">icon.svg</a></sub>
</p>

---

## Table of contents

- [What it does](#what-it-does)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Dashboard](#dashboard)
- [Desktop app](#desktop-app)
- [Telegram control](#telegram-control)
- [Watchdog and resilience](#watchdog-and-resilience)
- [Data and storage](#data-and-storage)
- [Project layout](#project-layout)
- [Scripts reference](#scripts-reference)
- [Troubleshooting](#troubleshooting)
- [Security and legal notice](#security-and-legal-notice)

---

## What it does

### Honeypot layer

| Component | Description |
|---|---|
| OpenCanary | Fake SMTP, HTTP, SSH, FTP, Telnet, MySQL, MSSQL, RDP, VNC, Redis, SNMP, NTP and more on 15+ ports |
| `protocols.py` | 15 extra fake services: SMTP, POP3, IMAP, PostgreSQL, Elasticsearch, Docker, Kubernetes, RTSP, Modbus, Memcached, DNS, MQTT, TeamViewer, LDAP, RMI |
| `usermodule.py` | Fake "CCTV-NVR admin API" exposed as an OpenCanary user module |
| `ingest.py` | Tails the OpenCanary log and writes parsed events to SQLite |
| `classifier.py` | Groups and scores repeated events (scan bursts, credential stuffing) |

### Host detection layer

| Component | Description |
|---|---|
| `procs.py` | Process start/exit monitor with optional ignore list |
| `usbdisk.py` | USB connect/disconnect, files copied from the device, Explorer open, execution |
| `netmon.py` | New outbound/inbound connections and listening sockets |
| `lannet.py` | Unknown devices appearing on the LAN (ARP table) |
| `clipboard.py` | Clipboard changes matching keyword or all-content mode |
| `camwatch.py` | Camera/microphone access by processes |
| `browserwatch.py` | Browsers opening `Login Data`, `Cookies` or `Local State` (credential theft) |
| `protect.py` | Folder watchdog (create/modify/delete) plus cleanup of old artifacts |
| `ransomware.py` | Ransomware tripwire: mass file changes inside a time window |
| `staging.py` | Data-staging detector: large archives created in user folders |
| `persist.py` | Persistence watchdog: new Run keys, startup folders, scheduled tasks |
| `theft.py` | Theft alarm: activity after idle/sleep that should not happen |
| `downloads.py` | Downloads sentinel: risky extensions and hashes |
| `secretscanner.py` | Scans file contents for tokens, keys and passwords |
| `sessions.py` | Windows logon/logoff/failed logon monitor (Security log) |
| `keylogger.py` | Local keystroke capture with sensitive-keyword alerts |
| `panic.py` | Panic actions: lock on brute force or USB grab, optional idle lock |
| `ipblocker.py` | Windows firewall auto-block after repeated failures |

### Deception layer

| Component | Description |
|---|---|
| `decoys.py` | Decoy credentials and files, access watcher, beacon callbacks, daily refresh |
| `honeytokens.py` | URL and credential honeytokens embedded in the dashboard |
| `embedtokens.py` | Hidden tokens inside normal-looking PNG / TXT / PDF files (LSB steganography, zero-width characters, PDF streams) |
| `lures.py` | Generates believable lure documents |

### Alerting layer

| Component | Description |
|---|---|
| `alerts.py` | Telegram, Discord, Slack and SMTP e-mail delivery |
| Severity filter | `min_severity`, per-category cooldowns, retry with backoff |
| Night escalation | 23:00-07:00 events are bumped one severity level; below `night_floor` is held for the morning digest |
| Batching | Groups bursts into a single message |
| Digest | Daily summary at 08:00 |
| Screenshots | Optional screen capture attached to selected categories |
| Mute | Silence individual categories at runtime |
| GeoIP | Country/city/org enrichment for source IPs |
| SIEM | Elasticsearch, Splunk HEC, generic HTTP and syslog exporters |

### Control layer

| Component | Description |
|---|---|
| `webapp.py` | Flask dashboard and JSON API on `127.0.0.1:8080` |
| `guardapp.py` | Native Tk desktop app (Overview / Events / Actions / Manage) |
| `tgbot.py` | In-process Telegram command bot (used when `telegram_bot.owner` is not `supervisor`) |
| `cgctl.py` | Always-on Telegram supervisor: keeps working when the main service is stopped |
| `control.py` | Runtime state, stop flag, start/stop/pause/resume/restart helpers |
| `tamper-check.ps1` | Per-minute watchdog: revives killed services, respects intentional stops |

---

## Architecture

```
                 +---------------------------+
   scanners ---> |  OpenCanary honeypot      | ---> opencanary.log
                 |  15+ fake services        |
                 +---------------------------+
                              |
                              v
                 +---------------------------+        +------------------+
                 |  Ingestor -> SQLite (WAL) | <----> |  Dashboard :8080 |
                 +---------------------------+        |  JSON API + UI   |
                              |                       +------------------+
                              v                                 ^
                 +---------------------------+                  |
                 |  Alerts (TG/Discord/...)  |                  |
                 +---------------------------+                  |
                                                                |
   +---------------------+     HTTP      +------------------+   |
   | guardapp.py (Tk)    | ------------> |  DashboardServer | --+
   +---------------------+               +------------------+
                                                  ^
   +---------------------+   /api/control/*      |
   | cgctl.py supervisor | ----------------------+
   | (always on)         |   schtasks /run, kill, state file
   +---------------------+
             ^
             | long-poll getUpdates
        Telegram group / channel
```

Key idea: the Telegram supervisor is a separate process. Stopping the main service never
stops the controller, so `/start` always works.

---

## Requirements

- Python 3.9+ (tested on 3.14, Windows 11)
- [OpenCanary](https://github.com/thinkst/opencanary) installed separately
- Python packages: `flask>=3.0`, `requests>=2.31`
- Optional: `psutil` (process monitor, runtime control), `watchdog` (folder monitor)
- Windows 10/11 for the full host feature set (sessions, keylogger, panic, USB, firewall block)
- Linux works for the honeypot, ingest, dashboard and alerting (host-specific modules are skipped)

---

## Installation

### Windows (recommended)

```powershell
# 1. install the package
pip install -e .

# 2. create the local configuration (never committed)
Copy-Item config.example.json config.json
#    then edit config.json: Telegram bot_token, chat_id, folders, drives...

# 3. run in the foreground once to verify
python main.py
```

Open <http://127.0.0.1:8080>.

To run everything in the background at logon, open PowerShell **as Administrator** and run:

```powershell
.\setup-background.ps1
```

This registers four scheduled tasks:

| Task | Purpose |
|---|---|
| `CanaryGuard` | starts `main.py` hidden at startup/logon |
| `OpenCanaryHoneypot` | starts the OpenCanary honeypot |
| `TamperGuard` | runs `tamper-check.ps1` every minute |
| `CanaryGuardControl` | keeps `cgctl.py` alive (every 5 minutes, idempotent) |

### Linux / Raspberry Pi

```bash
bash deploy-pi.sh            # installs OpenCanary, CanaryGuard and a systemd unit
# or manually:
pip install -e .
cp config.example.json config.json
python main.py
```

`deploy-pi.sh` is intended for an always-on box so alerts keep arriving while the Windows PC
is switched off.

---

## Configuration

All settings live in `config.json` (git-ignored). `config.example.json` is the documented
template. Top-level sections:

| Section | Purpose |
|---|---|
| `opencanary` | path to the OpenCanary log and the SQLite database |
| `alerts` | severity filter, cooldowns, batching, night escalation, digest, channels |
| `siem` | Elasticsearch, Splunk, HTTP and syslog exporters |
| `honeytokens` | URL and credential tokens |
| `dashboard` | bind address, port, auth mode, trusted networks |
| `ingest` | log polling interval and start position |
| `decoys` | decoy folder, beacon host, cooldown |
| `protect` | folder monitor, keylogger, sensitive keywords |
| `process_monitor` / `usb_monitor` / `netmon` / `clipboard_monitor` | host sensors |
| `telegram_bot` | bot ownership, allowed chats, admin users |
| `lan_monitor` / `downloads_monitor` / `cam_monitor` | LAN, downloads and camera sensors |
| `panic` | idle lock, lock on brute force, lock on USB grab |
| `secrets` | secret scanner and embedded honeytokens |
| `ransomware` / `staging` / `browser` / `persist` / `theft` / `evidence` | active-defense modules |
| `ipblock` | firewall auto-block thresholds |

Important keys:

```jsonc
{
  "dashboard": {
    "host": "0.0.0.0",
    "port": 8080,
    "password": "",                  // "" = local-only no-auth mode
    "noauth_allow_remote": false,    // keep false unless you really know why
    "trusted_networks": []           // CIDRs allowed without a password (VPN)
  },
  "telegram_bot": {
    "enabled": true,
    "owner": "supervisor",           // cgctl.py polls; main.py must not
    "allowed_chats": [],             // defaults to alerts.telegram.chat_id
    "admin_user_ids": []             // extra check inside groups
  }
}
```

---

## Dashboard

Default address: `http://127.0.0.1:8080`.

Two authentication modes:

1. **Password mode** - set `dashboard.password`. A login page is shown and a session cookie
   is issued.
2. **Local-only mode** - set `dashboard.password` to `""`. Unauthenticated access is allowed
   only from `127.0.0.1`, `::1` and any CIDR listed in `dashboard.trusted_networks`.
   LAN and internet clients receive `403` by design.

Recommended remote access: keep the dashboard local and connect through a VPN (WireGuard,
Tailscale, etc.). Do **not** port-forward the dashboard to the internet.

Main API endpoints:

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/stats` | GET | totals and counters |
| `/api/events` | GET | recent events |
| `/api/creds` / `/api/tokens` / `/api/sessions` / `/api/keys` | GET | captured data |
| `/api/files` / `/api/processes` / `/api/usb` / `/api/net` | GET | host activity |
| `/api/monitors` | GET | monitor status |
| `/api/monitors/<name>` | POST | enable/disable a monitor |
| `/api/lock` / `/api/panic` | POST | lock the PC / panic action |
| `/api/mute` / `/api/unmute` | POST | silence a category |
| `/api/digest` / `/api/screenshot` | POST/GET | send a digest / capture the screen |
| `/api/ipblock/*` | GET/POST | manage blocked IPs |
| `/api/control/state` | GET | runtime mode, uptime, PIDs, monitor count |
| `/api/control/pause` / `resume` / `stop` / `restart` | POST | runtime control |

---

## Desktop app

`guardapp.py` is a native Tk application that talks to the same dashboard API.

```powershell
python guardapp.py
```

- Opens with a splash screen and retries every 3 seconds until the dashboard answers.
- Goes straight to the main window in local-only mode; falls back to a login form only on
  `401`/`403`.
- Tabs: **Overview** (state badge, counters, monitors), **Events**, **Actions** (lock, panic,
  screenshot, test alert, digest, mute/unmute, IP block) and **Manage** (enable/disable
  monitors).
- UI exceptions are written to `%LOCALAPPDATA%\CanaryGuard\guardapp.err.log`.

---

## Telegram control

CanaryGuard uses a dedicated supervisor process (`cgctl.py`) for Telegram. It is started by
the `CanaryGuardControl` scheduled task and is independent from `main.py`.

Why: only one process may long-poll `getUpdates` for a bot token. When both `main.py` and the
supervisor poll, Telegram returns `409 Conflict`. With `telegram_bot.owner = "supervisor"`
(default), `main.py` disables its in-process bot and the supervisor owns the token. The
supervisor stays alive after `/stop`, so `/start` can always bring the stack back.

### Commands

Slash commands and plain words both work (`stop`, `/stop`, `/stop@YourBot`).

| Command | Action |
|---|---|
| `/status` | mode, uptime, dashboard state, PIDs, event counts, monitors |
| `/start` | start the service through its scheduled task |
| `/stop` | full stop: write `tamper.stopped`, graceful API stop, hard kill fallback |
| `/sleep` (`/pause`) | stop all monitors, keep the dashboard online |
| `/resume` (`/wake`) | restart all monitors |
| `/restart` | restart the service |
| `/digest` | send a summary now |
| `/screenshot` | capture the screen and send it |
| `/lock` | lock the PC |
| `/procs` | top CPU processes |
| `/mute <category>` / `/unmute <category>` | silence or re-enable a category |
| `/id` | show chat id, type, sender id and whether access is allowed |
| `/help` | command list |

### Authorisation

- `telegram_bot.allowed_chats` - chats allowed to send commands. Defaults to
  `alerts.telegram.chat_id`. `@username` entries are accepted too.
- `telegram_bot.admin_user_ids` - when set, commands inside groups/supergroups are only
  accepted from these user ids.
- Channel posts are authorised by the chat allowlist.
- Ordinary conversation is ignored: only known commands are handled.

Send `/id` from the group or channel to learn the exact ids to put in the config.

### Stop semantics

`/stop` writes the file `tamper.stopped` next to the project. `tamper-check.ps1` checks for
it and will not revive the service while it exists. `/start` removes the flag and runs the
`CanaryGuard` scheduled task.

---

## Watchdog and resilience

`tamper-check.ps1` runs every minute through the `TamperGuard` task:

- Fast TCP probes: dashboard on `127.0.0.1:8080`, honeypot on `127.0.0.1:9200`.
- A 5-minute cooldown file per service prevents revive storms.
- If `tamper.stopped` exists, the CanaryGuard revive is skipped on purpose.
- The control supervisor is revived if `cgctl.py` is not running.
- `tamper.mute` silences Telegram alerts during maintenance.

Additional protections in the main process:

- Windows named mutex `Local\CanaryGuardSingleInstance` - one instance only.
- `SetThreadExecutionState` keep-awake thread plus `powercfg` changes - the PC never sleeps
  or turns the display off while CanaryGuard runs.
- SQLite in WAL mode with `busy_timeout` and a single shared log store - no `database is
  locked` errors.
- `runtime_state.json` records the current mode, since, reason and PID.

---

## Data and storage

Everything is stored locally in `canaryguard.db` (git-ignored):

| Table | Content |
|---|---|
| `events` | normalised OpenCanary events |
| `alerts` | delivered alerts |
| `held_alerts` | alerts held for the morning digest |
| `creds` | captured honeypot credentials |
| `sessions` | Windows logon sessions |
| `keystrokes` | local keystroke buffer |
| `file_events` | folder watchdog activity |
| `process_events` | process start/exit |
| `usb_events` | USB activity |
| `net_events` | network connections |
| `clipboard_events` | clipboard changes |
| `cam_events` | camera/microphone access |
| `secret_hits` | secret scanner matches |
| `decoys` / `token_trips` | decoy inventory and access trips |
| `ip_meta` | GeoIP cache |

Daily evidence backups are compacted to the last 90 days of events and sent to Telegram as
`evidence_<timestamp>.zip`. Each archive contains a single `canaryguard.db` file. Leftover
archives in the project folder contain captured credentials, keystrokes and host activity, so
they are git-ignored and should be treated as sensitive.

Never commit: `config.json`, `*.db`, `*.log`, `evidence_*.zip`, `CanaryDecoys/`.

---

## Project layout

```
canaryguard/
├── main.py                     # entry point, wires every module
├── cgctl.py                    # always-on Telegram control supervisor
├── guardapp.py                 # Tk desktop app
├── honeytoken_builder.py       # GUI honeytoken creator
├── make_decoys.py              # CLI decoy generator
├── config.example.json         # configuration template (no secrets)
├── assets/                     # logo + app icon (PNG / SVG / ICO)
├── tools/make_logo.py          # regenerates the logo and icon set
├── pyproject.toml
├── requirements.txt
├── canaryguard/
│   ├── alerts.py               # Telegram / Discord / Slack / e-mail (+ inline buttons)
│   ├── beacon.py               # C2 beacon periodicity detection
│   ├── changepoint.py          # CUSUM event-rate change-point detector
│   ├── commonpass.py           # Bloom filter of breached passwords
│   ├── credgraph.py            # credential-stuffing/spray clustering
│   ├── cryptostore.py          # at-rest Fernet encryption helpers
│   ├── incidents.py            # kill-chain incident reconstruction
│   ├── luredoc.py              # watermarked lure document generator
│   ├── maintenance.py          # retention purge / VACUUM job
│   ├── markov.py               # scripted-vs-human shell heuristic
│   ├── paths.py                # portable path resolution (CANARYGUARD_HOME)
│   ├── playbooks.py            # SOAR-lite playbooks engine
│   ├── processgraph.py         # parent→child process rarity
│   ├── rarity.py               # (service, category) rarity scoring
│   ├── spray.py                # credential spray/fan-out detector
│   ├── stix.py                 # STIX 2.1 bundle export
│   ├── threatfeed.py           # threat-intel feed loading + lookup
│   ├── validation.py           # config.json validation at startup
│   ├── browserwatch.py         # browser credential-file access
│   ├── camwatch.py             # camera / microphone access
│   ├── classifier.py           # event grouping and scoring
│   ├── clipboard.py            # clipboard monitor
│   ├── config.py               # config loader
│   ├── control.py              # runtime state + start/stop/pause/resume
│   ├── decoys.py               # decoy files, watchers, beacons
│   ├── downloads.py            # downloads sentinel
│   ├── embedtokens.py          # hidden tokens in PNG / TXT / PDF
│   ├── evidence.py             # daily compact DB backup to Telegram
│   ├── fortress.py             # extra hardening helpers
│   ├── geolocate.py            # GeoIP enrichment
│   ├── honeytokens.py          # URL / credential tokens
│   ├── ingest.py               # OpenCanary log -> SQLite
│   ├── ipblocker.py            # firewall auto-block
│   ├── keylogger.py            # keystroke capture
│   ├── lannet.py               # LAN device discovery
│   ├── logstore.py             # SQLite schema and queries
│   ├── lures.py                # lure document generator
│   ├── netmon.py               # network connections
│   ├── panic.py                # panic / idle lock
│   ├── persist.py              # persistence watchdog
│   ├── phoneglow.py            # phone / hotspot helper
│   ├── procs.py                # process monitor
│   ├── protect.py              # folder watchdog + cleanup
│   ├── protocols.py            # 15 extra fake OpenCanary services
│   ├── ransomware.py           # ransomware tripwire
│   ├── secretscanner.py        # secret scanner
│   ├── sessions.py             # Windows logon monitor
│   ├── siem.py                 # Elasticsearch / Splunk / HTTP / syslog
│   ├── staging.py              # data-staging detector
│   ├── tgbot.py                # in-process Telegram bot
│   ├── theft.py                # theft alarm
│   ├── usbdisk.py              # USB monitor
│   ├── usermodule.py           # fake CCTV-NVR API module
│   ├── webapp.py               # Flask dashboard + JSON API
│   └── wifiwatch.py            # Wi-Fi / network helper
├── templates/index.html        # dashboard UI
├── static/                     # dashboard assets
├── start-canaryguard.ps1       # hidden launcher for main.py
├── start-control.ps1           # hidden launcher for cgctl.py
├── tamper-check.ps1            # per-minute watchdog
├── setup-background.ps1        # registers the scheduled tasks (admin)
├── open-port-8080.ps1          # firewall rule helper (admin)
├── run-setup.ps1               # wrapper for setup-background.ps1
└── deploy-pi.sh                # Linux / Raspberry Pi deployment
```

---

## Scripts reference

| Script | Runs as | Purpose |
|---|---|---|
| `start-canaryguard.ps1` | scheduled task | pulls the latest code, starts `main.py` hidden with logs |
| `start-control.ps1` | scheduled task | starts `cgctl.py` hidden if it is not already running |
| `tamper-check.ps1` | scheduled task, every minute | health probes, revive, alerts |
| `setup-background.ps1` | Administrator | creates the scheduled tasks |
| `run-setup.ps1` | user | wrapper that logs setup output |
| `open-port-8080.ps1` | Administrator | creates the firewall rule and prints router steps |
| `deploy-pi.sh` | root on Linux | installs OpenCanary + CanaryGuard + systemd |
| `open-honeytoken-builder.ps1` | user | opens the honeytoken GUI |

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `403` from another machine | Local-only mode is working as designed. Use a VPN or add a CIDR to `dashboard.trusted_networks`. |
| `409 Conflict` in Telegram | Two pollers on one token. Set `telegram_bot.owner` to `"supervisor"` and make sure `main.py` was restarted. |
| Dashboard does not come back after `/stop` | Send `/start`. The supervisor is independent, so this always works. |
| Watchdog revives the service after an intentional stop | `tamper.stopped` is missing. `/stop` creates it; do not delete it manually while stopped. |
| `database is locked` | Only one process should own the DB. The mutex, WAL mode and shared log store prevent this; check for stray `main.py` processes. |
| Port 8080 already in use | `netstat -ano | findstr :8080`, stop the other process, then restart the task. |
| No Telegram alerts | Check `alerts.telegram.bot_token` / `chat_id`, then send `/status` to the supervisor. |
| Desktop app shows "dashboard offline" | Start the service (`/start` or the scheduled task). The app retries every 3 seconds. |
| High idle CPU | `browserwatch` throttles `open_files()`; if you added custom monitors, check them with `py-spy`. |

---

## Security and legal notice

- `config.json`, `*.db`, `*.log`, `evidence_*.zip` and `CanaryDecoys/` are git-ignored.
  Keep it that way.
- The Telegram bot token and dashboard credentials are secrets. Rotate the token in
  BotFather if it was ever exposed.
- Captured keystrokes, credentials, sessions and screenshots are personal data. Store them
  only on systems you own and protect the database and evidence archives.
- This is a defensive honeypot and monitoring tool. Use it only on machines and networks you
  own or are explicitly authorised to monitor. Never plant real credentials as decoys and
  never deploy it against third parties.

---

## Development status & roadmap (2026-11)

The full analysis lives in [`docs/ANALYSIS-AND-ROADMAP.md`](docs/ANALYSIS-AND-ROADMAP.md).
What has been implemented so far on the development branch:

### Security & stability fixes
- UTC/local time skew fixed everywhere (`datetime('now','localtime', …)`) — 24h stats, digests, purges.
- SIEM forwarder: **bounded drop-oldest queue** (no more OOM while the SIEM is down), secret scrubbing
  before egress, TLS-verify options, optional TCP syslog.
- Ingest: **log rotation/truncation detection** (size + inode) — the tail no longer stalls forever.
- **At-rest encryption** (Fernet/AES) for captured credentials, keystrokes and secret-scanner hits.
  Legacy plaintext rows are re-encrypted automatically on first start. Key from `CANARYGUARD_SECRET_KEY`
  or `<home>/secret.key` (auto-generated, chmod 600). New dep: `cryptography`.
- Nightly evidence zip can be encrypted with a **user-held key** (`evidence.encryption_key`).
- `start-canaryguard.ps1` auto `git pull` is now **opt-in** (`CANARYGUARD_AUTO_UPDATE=1`).
- All hard-coded machine paths removed — scripts derive locations from `$PSScriptRoot`/`~`/`CANARYGUARD_HOME`.
- Config validation at startup (`canaryguard/validation.py`) — all problems printed in one pass.
- Daily **retention job** purges old rows per table (`retention.*`), optional VACUUM.
- Python ≤ 3.11 compatible f-strings; 48 pytest tests; GitHub Actions CI (3.9 + 3.12).

### New analytics (on by default, tune with `analytics.*`)
| Feature | Module | Endpoint |
|---|---|---|
| Rarity ("surprisingness") severity boost | `rarity.py` | (ingest path) |
| CUSUM change-point on event rate | `changepoint.py` | (ingest path) |
| Credential-spray / username-fanout detection | `spray.py` | `credential_spray` alert |
| Common/breached-password Bloom filter | `commonpass.py` | (ingest creds path) |
| Credential-graph clustering (stuffing botnets) | `credgraph.py` | `/api/credgraph` |
| Kill-chain incidents (MITRE labels) | `incidents.py` | `/api/incidents`, `/api/incidents/<ip>` |
| Parent→child process rarity (B1) | `processgraph.py` | `proc:rare_parent` alert |
| Ransomware entropy + extension-shift layers | `ransomware.py` | `ransomware:detected` |
| Threat-intel feeds (opt-in, `threatintel.*`) | `threatfeed.py` | `/api/intel/<ip>` |
| C2 beacon periodicity detection | `beacon.py` | `/api/beacons` |
| Scripted vs human shell heuristic | `markov.py` | (library) |
| Human triage feedback (tp/fp) | `logstore.feedback*` | `POST /api/feedback`, `/api/feedback/stats` |

### Operational features
- **Playbooks engine** (SOAR-lite): JSON rules in `playbooks.rules` or `<home>/playbooks.json`
  (`block_ip` / `notify` / `log` actions) — `playbooks.py`.
- **STIX 2.1 export** of high-severity attacker IPs — `/api/export/stix?hours=24` (`stix.py`).
- **Telegram inline buttons** on high/critical alerts `[Ack] [Mute] [Block IP]` via cgctl.py
  (`alerts.inline_buttons`).
- **Watermarked decoy documents** (zero-width TXT + marked PDF) — `canaryguard/luredoc.py`:
  `python -m canaryguard.luredoc --kind pdf --out ~/Desktop/vpn-creds.pdf`
- **`/api/health`** liveness endpoint.
- **Docker**: `Dockerfile` + `docker-compose.yml` (dashboard on 127.0.0.1:8080; mount `config.json` and the
  OpenCanary log). **CI**: `.github/workflows/ci.yml`.

### Running the tests

```bash
pip install -e . && pip install pytest
python -m pytest tests/ -q
```

### Not yet implemented (next iterations)
Isolation-Forest scoring (A1), scanner fingerprinting (A6), dynamic per-attacker honey-DB (C1/C2),
anti-fingerprinting of fake services (C4), PWA dashboard, fleet mode, STIX → MISP push, D3 Prometheus
`/metrics`. See the roadmap doc for the full list.

---

## License

No license file is included in this repository. Treat it as private software unless a license
is added.
