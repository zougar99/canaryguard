# Changelog

## [1.1.0] - 2026-11-05

### Application & platform
- Demo mode: `python -m canaryguard.demo` seeds a believable 7-day attack history (attacks, creds,
  GeoIP, sessions, beacon, token trips) and serves the dashboard — zero setup, zero real data.
- Progressive Web App: installable dashboard (manifest + service worker + canary icons), offline-aware.
- Windows installer pipeline (`packaging/windows/`): PyInstaller exes + Inno Setup `.iss`, scriptable
  release automation; GitHub Release workflow builds exes/installer on `v*` tags.
- New tests (52) + GitHub Actions CI (Python 3.9 / 3.12) and release workflow.
- `python -m canaryguard.setup_admin` — bootstrap/reset the dashboard admin password
  (interactive, `--generate`, or explicit; updates config.json with a .bak backup).

### Security fixes
- UTC/local time skew in all SQL "last N hours" filters and evidence purge.
- SIEM forwarder: bounded drop-oldest queue, secret scrubbing, TLS verification, optional TCP syslog.
- Ingest: log rotation/truncation detection (size + inode) — tailing no longer stalls silently.
- At-rest Fernet encryption for captured creds / keystrokes / secret-scanner values (+ legacy migration).
- Evidence zip: optional user-held encryption key (`evidence.encryption_key`).
- `start-canaryguard.ps1` auto `git pull` is opt-in (`CANARYGUARD_AUTO_UPDATE=1`).
- All hard-coded machine paths removed (`CANARYGUARD_HOME`, `$PSScriptRoot`, `~`).
- Cooldown comparisons no longer suppress alerts in the seconds right after boot
  (monotonic clocks are not safe against a zero baseline — fixed across 14 call sites).
- Python ≤ 3.11 compatibility fixes (backslash in f-string expressions).

### Analytics & detection
- A2 CUSUM change-point detector on the event rate (robust MAD baseline).
- A3 rarity scoring: severity bump for barely-seen (service, category) pairs.
- A4 credential-graph clustering (`/api/credgraph`), A12 credential spray / username fan-out alerts.
- A5 Bloom filter of breached/common passwords (local, offline).
- A7 beacon periodicity detection (`/api/beacons`), A8 scripted-vs-human shell heuristic (`markov.py`).
- A9 kill-chain incident reconstruction with MITRE labels (`/api/incidents`, `/api/incidents/<ip>`).
- A10 human triage feedback (`POST /api/feedback`), A11 opt-in threat-intel feeds (`/api/intel/<ip>`).
- B1 parent→child process rarity alerts (`proc:rare_parent`), B3 ransomware entropy/extension-shift.

### Operations
- Playbooks engine (SOAR-lite): JSON rules → block_ip / notify / log (`playbooks.py`).
- STIX 2.1 export (`/api/export/stix`), `/api/health`, retention job, config validation at startup,
  Telegram inline buttons [Ack] [Mute] [Block] (`alerts.inline_buttons`).
- Watermarked lure documents (`luredoc.py`), Dockerfile + docker-compose.

## [1.0.0] - 2026-06-01
Initial public release: OpenCanary integration, host sensors, decoys, embedded honeytokens,
Telegram/Discord/Slack/e-mail alerting, dashboards, stock tamper watchdog.
