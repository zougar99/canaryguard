<p align="center">
  <img src="assets/logo.png" alt="CanaryGuard logo" width="132">
</p>

<h1 align="center">CanaryGuard</h1>

<p align="center">
  <b>Self-hosted honeypot + host intrusion detection + remote control, built for Windows.</b>
</p>

CanaryGuard sits on top of [OpenCanary](https://github.com/thinkst/opencanary) and turns a
single machine into a monitored decoy host: fake network services attract scanners, local
sensors watch the real host, everything is stored in SQLite, and every meaningful event can
reach your phone through Telegram, Discord, Slack, e-mail or a SIEM.

The whole stack can be paused, stopped, restarted or brought back from a Telegram group or
channel — even when the main service is completely down. **No console window ever appears**:
every service, every helper process and every task switch runs hidden in the background.

<p align="center">
  <sub>Logo and app icon live in <a href="assets/">assets/</a> · vector versions:
  <a href="assets/logo.svg">logo.svg</a> · <a href="assets/icon.svg">icon.svg</a></sub>
</p>

---

## Table of contents

- [What it does](#what-it-does)
- [How it works, from A to Z](#how-it-works-from-a-to-z)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation — Windows from zero](#installation-windows-from-zero)
  - [1. Install Python](#1-install-python)
  - [2. Get the project](#2-get-the-project)
  - [3. Install dependencies](#3-install-dependencies)
  - [4. Create config.json](#4-create-configjson)
  - [5. Test in the foreground](#5-test-in-the-foreground)
  - [6. Run it in the background, forever](#6-run-it-in-the-background-forever)
  - [7. Verify everything is really hidden](#7-verify-everything-is-really-hidden)
- [Get notifications set up (Telegram, Discord, Slack, e-mail)](#get-notifications-set-up-telegram-discord-slack-e-mail)
- [Remote access and the reverse way back](#remote-access-and-the-reverse-way-back)
- [Configuration](#configuration)
- [Dashboard](#dashboard)
- [Desktop app](#desktop-app)
- [Telegram control](#telegram-control)
- [Watchdog and background operation](#watchdog-and-background-operation)
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
| `guardapp.py` | Native Tk desktop control panel (Dashboard / Events / Actions / Monitors / Blocklist) |
| `templates/index.html` | Dark/light operator web UI: sidebar, KPIs, live feed, IP drill-down, local attacker map |
| `templates/console.html` | Fullscreen NOC view fed by server-sent events (`/api/stream`) |
| `tgbot.py` | In-process Telegram bot (used when `telegram_bot.owner` is not `supervisor`) |
| `cgctl.py` | Always-on Telegram supervisor: keeps working when the main service is stopped |
| `control.py` | Runtime state, stop flag, start/stop/pause/resume/restart helpers |
| `_winproc.py` | Shared helper: every spawned command runs with `CREATE_NO_WINDOW` |
| `tamper-check.ps1` | Per-minute watchdog: revives killed services, respects intentional stops |

---

## How it works, from A to Z

### The startup sequence (what happens when you log in)

```mermaid
sequenceDiagram
    participant OS as Windows
    participant CG as CanaryGuard task<br/>(start-canaryguard.ps1)
    participant OC as OpenCanaryHoneypot task
    participant CTRL as CanaryGuardControl task<br/>(start-control.ps1)
    participant MAIN as main.py
    participant WATCH as TamperGuard task<br/>(tamper-check.ps1)

    OS->>CG: logon (hidden, no window)
    OS->>OC: logon (hidden, no window)
    OS->>CTRL: every 5 min + logon (idempotent)
    OS->>WATCH: every 1 minute
    CG->>CG: git pull (optional self-update)
    CG->>MAIN: python -u main.py (window hidden, output → guard.out.log)
    CTRL->>CTRL: cgctl.py supervisor (idempotent: refuses a second copy)
    MAIN->>MAIN: named mutex — only one instance survives
    MAIN->>MAIN: load config.json, open SQLite (WAL + busy_timeout)
    MAIN->>MAIN: start ingest loop, every monitor, webapp on :8080
    WATCH->>WATCH: TCP probe 8080 / 9200, revive with 5-min cooldown
```

- The launcher scripts run detached (`Start-Process -WindowStyle Hidden`).
- Every scheduled task has `<Hidden>true</Hidden>` in its definition, so it never shows a taskbar icon either.
- `main.py` writes its log to `guard.out.log`; the supervisor logs to `control.out.log`; the watchdog logs to `tamper.log`.

### The event pipeline (an attacker hits the honeypot)

```mermaid
flowchart TD
    A[Scanner hits fake service] --> B[OpenCanary writes opencanary.log]
    B --> C{Ingestor poll<br/>every 2 s}
    C --> D[Parse + normalise event]
    D --> E[INSERT into SQLite<br/>WAL + busy_timeout]
    E --> F[Classifier: score / group<br/>scan burst, credential stuffing]
    F --> G{Severity filter}
    G -->|below min_severity| X[drop]
    G -->|muted category| X
    G -->|duplicate in cooldown| X
    G -->|night 23-07 and below night_floor| H[hold in held_alerts]
    H --> I[08:00 digest]
    G -->|ok| J{Batch window}
    J --> K[Send to all enabled channels:<br/>Telegram / Discord / Slack / e-mail]
    K --> L[SIEM forward / screenshot attach]
    E --> M[Dashboard API reads SQLite]
    E --> N[Evidence backup daily 02:00<br/>max_mb size cap]
```

Key points:

1. The ingest loop never blocks the monitors — it polls the OpenCanary log on its own thread.
2. Writes are WAL-mode, so the dashboard can read while monitors write.
3. Night-mode alerts below the floor are **held, not lost** — they go out in the 08:00 digest.
4. Every delivery failure uses backoff-retry; a dead channel never stalls the loop.

### The control plane (how /stop and /start actually work)

```mermaid
sequenceDiagram
    actor U as You (Telegram)
    participant BOT as CanaryGuardControl<br/>(cgctl.py, always on)
    participant API as main.py dashboard<br/>(:8080)
    participant TASK as CanaryGuard task
    participant WATCH as tamper-check.ps1

    U->>BOT: /stop
    BOT->>BOT: write tamper.stopped
    BOT->>API: POST /api/control/stop (graceful)
    API->>API: stop monitors, set state=stopped
    BOT->>BOT: hard-kill fallback if still listening
    WATCH->>WATCH: sees 8080 down, sees tamper.stopped,<br/>does NOT revive (intentional stop)
    U->>BOT: /sleep (pause)
    BOT->>API: POST /api/control/pause
    API->>API: stop monitors, dashboard stays up
    U->>BOT: /start
    BOT->>BOT: remove tamper.stopped, state=starting
    BOT->>TASK: schtasks /run /tn CanaryGuard
    TASK->>API: main.py boots, state=running
```

Critical rule: `TamperGuard` only revives the dashboard when `tamper.stopped` does **not**
exist. Intentional stops survive reboots; crashes get revived within a minute.

### The read path (you open the dashboard)

1. Browser calls `GET /api/overview` (one JSON bundle: stats, monitors, control state, blocked IPs, night info).
2. The web UI renders KPIs, the SVG activity chart, severity donut, attacker map (offline centroids, no external geocoder) and live feed.
3. The **NOC console** (`/console`) keeps that connection open as server-sent events (`/api/stream`) and just re-renders every 3 s.
4. The desktop app polls the same API every **6 s** in a background thread — the UI thread never blocks.
5. Everything is local; nothing is sent anywhere except the alert channels you enable.

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
                               v                                 ^   ^
                  +---------------------------+                  |   | SSE
                  |  Alerts (TG/Discord/...)  |                  |   |
                  +---------------------------+                  |   |
                                                                |   |
    +---------------------+     HTTP      +------------------+  |   |
    | guardapp.py (Tk)    | ------------> |  DashboardServer | --+   |
    +---------------------+               +------------------+       |
                                                   ^                 |
    +---------------------+   /api/control/*      |                 |
    | cgctl.py supervisor | ----------------------+                 |
    | (always on, hidden) |   schtasks /run, kill, state file       |
    +---------------------+                                        |
              ^                                                    |
              | long-poll getUpdates                               |
         Telegram group / channel          -------------------------+
```

Key idea: the Telegram supervisor is a separate, always-on process. Stopping the main
service never stops the controller, so `/start` always works.

---

## Requirements

| Requirement | Why | Notes |
|---|---|---|
| Python 3.9+ (tested on 3.14, Windows 11) | runtime | the `WindowsApps` alias can interfere — install from python.org |
| [OpenCanary](https://github.com/thinkst/opencanary) | the honeypot itself | installs from `requirements.txt` as `opencanary` |
| `flask>=3.0` | dashboard / JSON API | |
| `requests>=2.31` | Telegram API, Discord/Slack webhooks, GeoIP, SIEM | no Telegram SDK needed — plain HTTP |
| `psutil>=5.9` | process monitor, PIDs in `/status`, CPU leaderboard, runtime control | |
| `watchdog>=4.0` | folder watchers (downloads sentinel, staging, lures) | |
| `Pillow>=10.0` | screenshots in alerts, embedded-token stash, desktop app icons | |
| `tkinter` | desktop app | ships with Python on Windows; Linux: `sudo apt install python3-tk` |
| Windows 10/11 for host features | sessions, keylogger, panic, USB, firewall block | on Linux those modules stay disabled; honeypot/ingest/dashboard/alerts work |
| Admin rights for the Security log monitor | `Security` event log is admin-only | dashboard still works without it |
| VPN for remote access | the dashboard is local-only by design | see [Remote access](#remote-access-and-the-reverse-way-back) |

Every Python package the project imports — nothing else is needed:

```
flask>=3.0          requests>=2.31      psutil>=5.9
watchdog>=4.0       Pillow>=10.0        opencanary
```

(Standard-library modules used: `sqlite3`, `smtplib`, `ctypes`, `winreg`, `threading`,
`zlib`, `zipfile`, `email.mime` — all built in.)

---

## Installation — Windows from zero

> Everything below is tested on Windows 11 with Python 3.14 and behaves the same on Windows 10.

### 1. Install Python

1. Download Python from <https://www.python.org/downloads/windows/> — pick the "Latest Python 3 Release".
2. Run the installer. On the first screen **tick"Add python.exe to PATH"**.
3. Open *Command Prompt* and verify:

```
python --version
```

Expected: `Python 3.14.x` (or newer). If you get "Python was not found", the box was not ticked —
re-run the installer and choose *Modify* → tick it, or use `py --version` if the launcher is present.

### 2. Get the project

```powershell
git clone https://github.com/zougar99/canaryguard.git
cd canaryguard
```

(or download the ZIP from the GitHub releases page and unzip it anywhere)

### 3. Install dependencies

```powershell
pip install -r requirements.txt
pip install -e .
```

- `pip install -e .` installs the project as a package; it also registers the OpenCanary user-modules
  (`canaryguard/protocols.py`, `canaryguard/usermodule.py`) with the `canary.usermodule` entry points.
- OpenCanary itself is installed by the same command (it is in `requirements.txt`).

### 4. Create config.json

```powershell
Copy-Item config.example.json config.json
notepad config.json
```

**Minimum you must change for a working local install** (the file ships with obviously fake defaults):

| Key | Set to |
|---|---|
| `opencanary.log_file` | path to your OpenCanary log, e.g. `C:\opencanary\opencanary.log` |
| `opencanary.db_file` | where events should be stored, e.g. `C:\Users\you\canaryguard\canaryguard.db` |
| `dashboard.password` | `""` for local-only no-auth **or** your password |
| `dashboard.secret_key` | a long random string |
| `alerts.telegram.bot_token` / `chat_id` | see [Get notifications set up](#get-notifications-set-up-telegram-discord-slack-e-mail) |
| `protect.folders` | your real `Desktop`, `Documents`, `Downloads` paths |
| `usb_monitor.watch_drives` | drives to watch, e.g. `["C:", "E:"]` |

For the full of each setting, see the field-by-field reference in [Configuration](#configuration).

### 5. Test in the foreground

```powershell
python main.py
```

You should see lines like:

```
[main] single instance enforced (Local\CanaryGuardSingleInstance)
[ingest] watching C:\opencanary\opencanary.log
[webapp] dashboard on http://127.0.0.1:8080
[main] monitors started: 16/16
```

Verify from a second terminal:

```powershell
(Test-NetConnection 127.0.0.1 -Port 8080).TcpTestSucceeded
curl.exe -s http://127.0.0.1:8080/api/control/state
```

`TcpTestSucceeded` must be `True`; the API prints a JSON object with `"mode":"running"`.
Press `Ctrl+C` to stop.

### 6. Run it in the background, forever

Open **PowerShell as Administrator** (`Win + X` → "Terminal (Admin)"):

```powershell
cd C:\Users\you\canaryguard
.\setup-background.ps1
```

This registers four scheduled tasks — **all of them hidden** (no window, no taskbar icon):

| Task | Purpose | Hidden |
|---|---|---|
| `CanaryGuard` | `start-canaryguard.ps1` → `main.py` at boot/logon | yes |
| `CanaryGuardControl` | `start-control.ps1` → `cgctl.py` Telegram supervisor, every 5 min | yes |
| `TamperGuard` | `tamper-check.ps1` every minute; revives killed services | yes |
| `OpenCanaryHoneypot` | starts the OpenCanary honeypot | yes |

- `start-canaryguard.ps1` also does `git pull` first (non-fatal), so a fresh checkout self-updates.
- `start-control.ps1` refuses to start a second copy — the task is idempotent.
- `tamper-check.ps1` uses a 5-minute cooldown per service so a crash loop cannot spawn storms.

**The PC never sleeps** while CanaryGuard runs (keep-awake via `powercfg` and
`SetThreadExecutionState`).

### 7. Verify everything is really hidden

```powershell
schtasks /query /tn CanaryGuard /xml | Select-String Hidden
schtasks /query /tn TamperGuard /xml | Select-String Hidden
schtasks /query /tn CanaryGuardControl /xml | Select-String Hidden
Get-Process python | Select-Object Id, ProcessName, MainWindowTitle
```

All four commands answer with `<Hidden>true</Hidden>` (uppercase or lowercase depending on locale),
and `MainWindowTitle` is empty for every Python process.

No cmd/PowerShell windows should pop up. If you still see one, note which task/command it is and
file it — every spawned command in the codebase deliberately uses `CREATE_NO_WINDOW`, and all
four launcher tasks run `-WindowStyle Hidden`.
---

## Get notifications set up (Telegram, Discord, Slack, e-mail)

> **Easier option:** open the web dashboard → **Notifications** tab. All three channels
> (Telegram, Discord, email) can be configured, saved and tested live — no file editing,
> no restart. The secrets you paste are masked in the UI and stored only in `config.json`.

You can enable any combination of the four channels — they don't exclude each other.
Below are the exact steps for each. Note that the **Test alert** button always sends through
**Telegram only** when triggered via `/api/test_alert`; the **Notifications** tab has a per-channel
**Send test** button.

### 1) Telegram (recommended)

**Step 1 — create the bot**

1. In Telegram, open **@BotFather**, send `/newbot`.
2. Pick a display name (e.g. `CanaryGuard`) and a username ending in `bot` (e.g. `canaryguard_alert_bot`).
3. BotFather replies with a token like `8795038472:AAG...` — this is your **bot token**.

**Step 2 — add the bot to your chat/group**

- Private alerts: open a chat with your bot, press **Start**, send any message (`/ping`).
- Group alerts: add the bot to the group. If the group is public it needs admin rights only if you
  want it to receive channel posts.
- Channel alerts: add the bot as a **channel administrator** (needed to post).

**Step 3 — get the chat id**

After sending a message in that chat, open this URL in a browser (replace `TOKEN`):

```
https://api.telegram.org/botTOKEN/getUpdates
```

Look for `"chat": { "id": ... }`:

- Private chat: a positive id, e.g. `123456789`
- Group: a negative id, e.g. `-4314752915`
- Supergroup / channel: `-100...`, e.g. `-1004314752915`

**Step 4 — put it in `config.json`**

```jsonc
{
  "alerts": {
    "enabled": true,
    "min_severity": "medium",           // low | medium | high | critical
    "telegram": {
      "enabled": true,
      "bot_token": "8795038472:AAH...",
      "chat_id": "-1004314752915"
    }
  },
  "telegram_bot": {
    "enabled": true,
    "owner": "supervisor",               // main.py stays quiet; cgctl.py polls
    "allowed_chats": [],                 // default: [alerts.telegram.chat_id]
    "admin_user_ids": []                 // optional: restrict group commands
  }
}
```

`allowed_chats` and `alerts.telegram.chat_id` are two different things: the **alerting chat** is
where notifications go; **allowed_chats** is who may send *commands* (`/stop`, `/status`...).
If `allowed_chats` is empty, only the alerting chat can command the bot.

To command the bot from a different group, put that group's id in `allowed_chats`.
To see the exact ids from inside Telegram, send `/id` to the bot (it replies with chat id, type
and sender id).

**Step 5 — restart and test**

```powershell
schtasks /run /tn CanaryGuard
curl.exe -s -X POST http://127.0.0.1:8080/api/test_alert
```

You should receive **TEST NOTIFICATION** in Telegram. `/status` in the chat answers with mode,
uptime, monitor count and PIDs.

**Rotate if leaked**

`@BotFather` → `/revoke` → confirm → new token → replace in `config.json` → restart the task.

**Error `409 Conflict`**

Telegram allows exactly one long-poll connection per bot. If you see this, a second process is
also polling (usually an old `main.py` or `cgctl.py`). Fix: keep `telegram_bot.owner = "supervisor"`
and make sure only one supervisor is running:

```powershell
Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*cgctl.py*' } | Select-Object ProcessId
```

### 2) Discord

1. Open your Discord server → **Server Settings → Integrations → Webhooks → New Webhook**.
2. Name it (e.g. `CanaryGuard`), pick the channel, press **Copy Webhook URL**.
   The URL looks like `https://discord.com/api/webhooks/123/abc...`.
3. `config.json`:

```jsonc
"discord": {
  "enabled": true,
  "webhook_url": "https://discord.com/api/webhooks/123456789/abcdef..."
}
```

4. Restart (`schtasks /run /tn CanaryGuard`). Alerts fire on the next qualifying event.

There is no separate Discord "bot" app and no SDK required — a webhook is a plain HTTPS POST.

### 3) Slack

1. Go to <https://api.slack.com/apps> → **Create New App → From scratch**, pick a name and workspace.
2. In the left menu open **Incoming Webhooks** → toggle **Activate Incoming Webhooks** on.
3. **Add New Webhook to Workspace** → pick the channel → **Allow**.
4. Copy the URL `https://hooks.slack.com/services/T.../B.../xxx` into `config.json`:

```jsonc
"slack": {
  "enabled": true,
  "webhook_url": "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
}
```

5. Restart the task. The message format is `*<subject>*` followed by a code block.

### 4) E-mail (SMTP, STARTTLS)

Portable config for Gmail (works with any SMTP provider — Outlook, Yahoo, your own mail server):

```jsonc
"email": {
  "enabled": true,
  "smtp_host": "smtp.gmail.com",
  "smtp_port": 587,
  "username": "you@gmail.com",
  "password": "YOUR_APP_PASSWORD",   // NOT your account password if 2FA is on
  "from_addr": "you@gmail.com",
  "to_addr": "you@gmail.com"         // can be a comma-separated list? no — single address
}
```

**Gmail — app password in 4 steps**

1. `myaccount.google.com` → **Security** → enable **2-Step Verification**.
2. Same page → **App passwords** → create, name it `canaryguard` → Google shows a 16-character password.
3. Use that 16-char password (spaces removed) as `password`.
4. Restart the task.

The code issues `STARTTLS` on port 587 (port 465 also uses STARTTLS). Your body is plain text
with the alert in it; the subject is the alert subject.

### 5) SIEM forwarders (optional, same relay)

```jsonc
"siem": {
  "elasticsearch": { "enabled": false, "url": "http://localhost:9200", "index": "opencanary-events" },
  "splunk":        { "enabled": false, "hec_url": "https://splunk:8088/services/collector", "token": "HEC-TOKEN" },
  "http":          { "enabled": false, "url": "https://siem.example/ingest", "headers": { "Authorization": "Bearer ..." } },
  "syslog":        { "enabled": false, "host": "127.0.0.1", "port": 514 }
}
```

### 6) Taming the noise

| Key | Purpose | Good starting point |
|---|---|---|
| `alerts.min_severity` | drop anything below this severity | `"medium"` |
| `alerts.cooldown_seconds` | suppress repeats of the same category | `60` |
| `alerts.batch_limit` / `batch_window_seconds` | bundle bursts into one message | `3` / `300` |
| `alerts.night_escalation` / `night_start` / `night_end` | bump +1 severity at night | `true` / `23:00` / `07:00` |
| `alerts.night_floor` | hold below this floor until the 08:00 digest | `"high"` |
| `alerts.digest_time` | when the digest is sent | `"08:00"` |
| `alerts.mute_categories` | hard-silence categories | `[]` |
| `alerts.screenshot_categories` | categories that attach a screenshot | `usb:connect`, `auth:fail`, `usb:exec` |
| `alerts.notify_on_start` | Telegram "started" message on boot | `true` |

**Test checklist after any channel change**

1. `schtasks /run /tn CanaryGuard` (or wait for the next event)
2. `curl.exe -s -X POST http://127.0.0.1:8080/api/test_alert`
3. `curl.exe -s http://127.0.0.1:8080/api/control/state`
4. Trigger an innocuous alert (e.g. copy a file into the `Downloads` folder with a suspicious extension) and confirm it arrives.

---

## Remote access and the reverse way back

The dashboard is **local by design** — do not port-forward 8080 to the internet.

Supported patterns:

| Pattern | How |
|---|---|
| VPN (WireGuard / Tailscale) | connect to your own network, browse `http://192.168.1.20:8080` — recommended |
| `trusted_networks` | CIDRs allowed without a password, e.g. `["10.8.0.0/24"]` — use only with a VPN |
| Password mode + reverse proxy | possible, but keep `noauth_allow_remote: false` and let the proxy terminate TLS + auth |
| Permanent outage protection | nothing — local-only is the point. Recovery happens through the Telegram supervisor (below) |

The `decoys.beacon_host` may be a public DDNS name — that is for *outbound* decoy callbacks, not
for exposing the dashboard.

The Telegram supervisor is the only piece that answers from anywhere. It works even if the
firewall blocks 8080 and even if OpenCanary, the dashboard and every monitor are stopped —
`cgctl.py` never depends on them.

**Recovery recipe** (you're abroad, everything's down, no shell access):

1. Send `/status` → answers anywhere.
2. Send `/start` → removes `tamper.stopped`, runs the `CanaryGuard` task.
3. `/sleep` then `/resume` if you want to keep the machine up but pause noisy monitoring.
4. `/lock` if you suspect someone else is using the PC.

---

## Configuration

All settings live in `config.json` (git-ignored; `config.example.json` is the template).
Important sections and their effect:

| Section | What it controls |
|---|---|
| `opencanary` | paths to the OpenCanary log and the SQLite database |
| `alerts` | severity filter, cooldowns, batching, night mode, 08:00 digest, channels |
| `siem` | Elasticsearch, Splunk, generic HTTP, syslog |
| `honeytokens` / `decoys` / `secrets` | deception assets and beacons |
| `dashboard` | bind host/port, password mode, trusted networks, secret key |
| `protect` | folders to watch, keylogger, sensitive keywords |
| `process_monitor` / `usb_monitor` / `netmon` / `clipboard_monitor` | host sensors |
| `lan_monitor` / `downloads_monitor` / `cam_monitor` | LAN / downloads / camera sensors |
| `panic` | lock on brute force, lock on USB grab, optional idle lock |
| `telegram_bot` | bot ownership, allowed chats, admin users |
| `ipblock` | firewall auto-block thresholds |
| `evidence` | daily compact backup to Telegram (time, max size) |

Minimal example of a fully working local install:

```jsonc
{
  "opencanary": { "log_file": "C:\\opencanary\\opencanary.log",
                  "db_file": "C:\\Users\\you\\canaryguard\\canaryguard.db" },
  "alerts": { "enabled": true, "min_severity": "medium",
              "telegram": { "enabled": true,
                            "bot_token": "...", "chat_id": "-100..." },
              "night_escalation": true, "night_start": "23:00", "night_end": "07:00" },
  "dashboard": { "host": "0.0.0.0", "port": 8080, "password": "",
                 "noauth_allow_remote": false, "trusted_networks": [] },
  "telegram_bot": { "enabled": true, "owner": "supervisor" }
}
```

---

## Dashboard

Default address: `http://127.0.0.1:8080`.

Two authentication modes:

1. **Password mode** — set `dashboard.password`. A login page is shown and a session cookie is issued.
2. **Local-only mode** — set `dashboard.password` to `""`. Unauthenticated access is allowed only
   from `127.0.0.1`, `::1` and CIDRs in `dashboard.trusted_networks`. Everyone else gets `403`.

**Views in the web UI (`/`)**

- Sidebar with **Overview / Live feed / Events / Control / … / Cleanup / About** sections, keyboard shortcuts (`1`–`9`, `/`, `r`, `t`).
- **Overview** — KPI cards (events, critical, credentials, monitors, uptime, blocked IPs), activity chart, severity donut, top attacker IPs, **attacker map** (offline country centroids, no external request).
- **Live feed** — real-time event stream with severity filters and text search.
- **Notifications** — configure and test Telegram / Discord / email channels live (saved to `config.json`, no restart).
- **Control** — Sleep / Resume / Restart / Stop, mute categories, firewall blocklist, monitor toggles.
- **Cleanup** — find and delete suspicious files in one click.
- **NOC console** (`/console`) — fullscreen wallboard fed by `/api/stream` (server-sent events); designed for an always-on second monitor.

**Key API endpoints**

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/overview` | GET | complete dashboard bundle |
| `/api/stream` | GET (SSE) | the same bundle every few seconds for the NOC console |
| `/api/stats` | GET | totals and counters |
| `/api/events` | GET | recent events |
| `/api/monitors` / `/api/monitors/<name>` | GET/POST | monitor status / enable / disable |
| `/api/control/state` | GET | runtime mode, uptime, PIDs, monitor count |
| `/api/control/pause` / `resume` / `stop` / `restart` | POST | runtime control |
| `/api/mute` / `/api/unmute` | POST | silence a category |
| `/api/ipblock/*` | GET/POST | manage blocked IPs |
| `/api/test_alert` | POST | send the Telegram test message |

---

## Desktop app

`guardapp.py` is a native Tk application that talks to the same local API.

```powershell
python guardapp.py
```

- **Control panel**, not a login form: you go straight into it. It shows a splash for up to ~60 s
  while the service boots; retries every 3 s; drops you into the dashboard when 200 replies.
- **Top bar** — CanaryGuard logo, "Open dashboard" button, live status line.
- **Control strip** — mode badge (`RUNNING` / `PAUSED` / `STOPPED`…) plus **Sleep / Resume /
  Restart / Stop** buttons. Stop asks for confirmation because the dashboard goes down.
- **Dashboard tab** — six KPI cards, monitors table, last events.
- **Events** — latest events, severity colours.
- **Actions** — lock PC, panic, screenshot, test alert, digest, mute/unmute, IP block.
- **Monitors** — enable/disable individual monitors.
- **Blocklist** — browse firewall rules.
- All polling runs on background threads; the UI never blocks.
- UI errors are appended to `%LOCALAPPDATA%\CanaryGuard\guardapp.err.log`.
- The app needs no window from the scheduled tasks — launching it is what you do, not part of
  the background stack.

---

## Telegram control

`cgctl.py` (the **supervisor**) owns the Telegram token and runs forever.

- Only one process may long-poll `getUpdates` — the supervisor owns it, `main.py` does nothing with
  Telegram when `telegram_bot.owner = "supervisor"` (default).
- It survives `/stop`. That is its whole purpose: `/start` works when everything else is dead.
- It is idempotent — starting it twice does not create a second bot.

**Commands** (slash, plain word or `/command@YourBot`):

| Command | Action |
|---|---|
| `/status` | mode, uptime, dashboard state, PIDs, monitors, event totals |
| `/start` | remove stop flag, run `CanaryGuard` task |
| `/stop` | write `tamper.stopped`, graceful API stop, hard kill fallback |
| `/sleep` / `/pause` | stop all monitors, dashboard stays |
| `/resume` / `/wake` | monitors back on |
| `/restart` | restart the service |
| `/digest` | send today's summary now |
| `/screenshot` | capture and send a JPEG |
| `/lock` | lock the workstation |
| `/procs` | top CPU processes |
| `/mute <cat>` / `/unmute <cat>` | silence a category |
| `/id` | show chat id, type, sender id (for allowlists) |
| `/help` | command list |

**Authorisation** — the bot ignores ordinary messages; only known commands are handled, and only
from chats in `telegram_bot.allowed_chats` (defaults to the alerting chat) or from
`telegram_bot.admin_user_ids` inside groups.

**Stop semantics** — `/stop` writes `tamper.stopped`. `TamperGuard` sees it and deliberately
refuses to revive CanaryGuard. Delete the flag (or send `/start`) to re-arm it.

---

## Watchdog and background operation

Everything runs hidden. Summary of what keeps it that way:

| Layer | How it stays invisible |
|---|---|
| `CanaryGuard` task | hidden task, `pwsh -WindowStyle Hidden` → `main.py` with output redirected to `guard.out.log` |
| `CanaryGuardControl` task | hidden task, `-WindowStyle Hidden` → `cgctl.py` → `control.out.log` |
| `TamperGuard` task | hidden task, `-WindowStyle Hidden` → `tamper-check.ps1` → `tamper.log` |
| `OpenCanaryHoneypot` task | hidden task, `-WindowStyle Hidden` |
| Helper processes | `canaryguard/_winproc.py` — every spawned command (`netsh`, `arp`, `schtasks`, `rundll32`, …) uses `CREATE_NO_WINDOW` |
| `os.system` | none left in the codebase; removed in favour of explicit subprocess calls |
| Logging | `guard.out.log`, `control.out.log`, `guard.err.log` — open these when in doubt |
| Watchdog | every minute: TCP probe 8080/9200, revive with 5-minute cooldown, Telegram alert (suppressed by `tamper.mute`) |
| Single instance | named mutex `Local\CanaryGuardSingleInstance` — duplicate boots exit immediately |
| Keep-awake | `SetThreadExecutionState` thread + `powercfg` — the PC never sleeps spontaneously |
| Cleanliness | `tamper.mute` suppresses maintenance alerts; `tamper.stopped` records intentional stops |

**Maintenance recipe**

```powershell
Set-Content tamper.mute "maintenance $(Get-Date -Format s)"
# ... do your thing ...
Remove-Item tamper.mute
schtasks /run /tn CanaryGuard
```

**If you ever see a window**

Note the title/process, then check `Get-Process` and report it — the design goal is **zero**
visible windows after login.

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
`evidence_<timestamp>.zip`. Archives contain a `canaryguard.db` snapshot with captured
credentials, keystrokes and host activity — treat them as sensitive, never commit them.

Never commit: `config.json`, `*.db`, `*.log`, `evidence_*.zip`, `CanaryDecoys/`.

---

## Project layout

```
canaryguard/
├── main.py                     # entry point, wires every module
├── cgctl.py                    # always-on Telegram control supervisor
├── guardapp.py                 # Tk desktop control panel
├── honeytoken_builder.py       # GUI honeytoken creator
├── make_decoys.py              # CLI decoy generator
├── config.example.json         # configuration template (no secrets)
├── assets/                     # logo + app icon (PNG / SVG / ICO)
├── tools/make_logo.py          # regenerates the logo and icon set
├── pyproject.toml
├── requirements.txt
├── canaryguard/
│   ├── _winproc.py             # shared hidden-subprocess helper (CREATE_NO_WINDOW)
│   ├── alerts.py               # Telegram / Discord / Slack / e-mail / SIEM
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
├── templates/
│   ├── index.html              # operator dashboard (sidebar / live feed / map)
│   ├── console.html            # /console — fullscreen NOC view (SSE)
│   └── login.html              # password-mode login
├── static/                     # dashboard favicon + logo
├── start-canaryguard.ps1       # hidden launcher for main.py
├── start-control.ps1           # hidden launcher for cgctl.py
├── tamper-check.ps1            # per-minute watchdog
├── setup-background.ps1        # registers the (hidden) scheduled tasks (admin)
├── open-port-8080.ps1          # firewall rule helper (admin)
├── run-setup.ps1               # wrapper for setup-background.ps1
└── deploy-pi.sh                # Linux / Raspberry Pi deployment
```

---

## Scripts reference

| Script | Runs as | Purpose |
|---|---|---|
| `start-canaryguard.ps1` | scheduled task | optional self-update, starts `main.py` hidden |
| `start-control.ps1` | scheduled task | starts `cgctl.py` hidden, idempotent |
| `tamper-check.ps1` | scheduled task, every minute | probe, revive, alert (hidden) |
| `setup-background.ps1` | Administrator | creates the scheduled tasks |
| `run-setup.ps1` | user | wrapper that logs setup output |
| `open-port-8080.ps1` | Administrator | firewall rule + router notes |
| `deploy-pi.sh` | root on Linux | OpenCanary + CanaryGuard + systemd |
| `open-honeytoken-builder.ps1` | user | honeytoken GUI |

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Still seeing a window flash | Check `Get-Process` title; make sure the 4 tasks are hidden (Step 7) and restart them. No helper process should use `os.system`. |
| `403` from another machine | Local-only mode is working as designed. Use a VPN, or add the CIDR to `dashboard.trusted_networks`. |
| `401/403` in the desktop app | A password is configured (or remote guard). Sign in once — the app retries afterwards. |
| `409 Conflict` in Telegram | Two pollers on one token. `telegram_bot.owner = "supervisor"`; restart. |
| No Telegram alerts | `alerts.telegram` disabled/empty; test with `/api/test_alert`; check `/id`. |
| No 08:00 digest | `held_alerts` populated? check `digest_time` and `night_floor`. |
| Dashboard doesn't come back after `/stop` | Send `/start` from Telegram — the supervisor is independent. |
| Watchdog keeps reviving after stop | `tamper.stopped` missing — do not delete it manually. |
| `database is locked` | Only one process should own the DB — check for stray `main.py` processes. |
| Port 8080 already in use | `netstat -ano \| findstr :8080`, kill the other process, rerun the task. |
| High idle CPU | `browserwatch` throttles `open_files()`; for custom modules check with `py-spy`. |
| Desktop app shows Offline | Dashboard is down — start the service; app retries every 6 s. |

---

## Security and legal notice

- `config.json`, `*.db`, `*.log`, `evidence_*.zip` and `CanaryDecoys/` are git-ignored.
- The Telegram bot token and dashboard credentials are secrets. Rotate the token in
  BotFather if it was ever exposed.
- Captured keystrokes, credentials, sessions and screenshots are personal data. Store them
  only on systems you own and protect the database and evidence archives.
- This is a **defensive** honeypot and monitoring tool. Use it only on machines and networks
  you own or are explicitly authorised to monitor. Never plant real credentials as decoys and
  never deploy it against third parties.

---

## License

No license file is included in this repository. Treat it as private software unless a license is added.
