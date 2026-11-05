# CanaryGuard — Code & Product Analysis + Development Roadmap

> **Implementation status (2026-11-05):** Quick wins ✅ · Phase 0 ✅ (all) · Phase 1 ✅
> (A2 changepoint, A3 rarity, A4 credgraph, A5 commonpass, A7 beacon, A8 markov, A9 incidents,
> A10 feedback, A11 threatfeed, A12 spray) · Phase 2 ✅ (B1 parent→child, B3 entropy, C5 watermarked
> lures, D7 Telegram inline buttons) · Phase 3 ✅ (D2 Docker, D4 retention, D5 validation, D9 STIX,
> D12 playbooks) · A1 isolation forest ❌, A6 scanner fingerprinting ❌, C1/C2 dynamic honey-DB ❌,
> C4 anti-fingerprinting ❌, D3 Prometheus ❌. 50 pytest tests green; CI runs 3.9 & 3.12.
>
> **Application layer (1.1.0, 2026-11-05):** demo mode (`python -m canaryguard.demo`, seeded
> 7-day attack history), installable PWA (manifest + service worker + canary icons), Windows
> installer pipeline (`packaging/windows/`, PyInstaller + Inno Setup), GitHub Release workflow
> (tag `v*` → exes + installer + sdist/wheel). See CHANGELOG.md and README (Demo mode /
> Install as an app / Windows installer).

Analysis date: 2026-11-05 · Scope: full repo (`main` @ `e07e54f`, ~7,450 LOC Python, 44 modules, 0 tests, no CI)

This document is an honest review of what exists today, a list of concrete bugs/risks found while
reading the code, and a prioritised set of algorithms and features you can add next.

---

## 1. Snapshot — what this project is

CanaryGuard is a **self-hosted honeypot + host intrusion detection + remote-control stack** for a
single Windows PC (with a Linux/Pi path for the honeypot part). Five layers:

| Layer | Modules | Maturity |
|---|---|---|
| Honeypot | `protocols.py` (15 fake services), `usermodule.py`, `ingest.py`, `classifier.py` | Solid |
| Host sensors | `procs`, `usbdisk`, `netmon`, `sessions`, `keylogger`, `browserwatch`, `camwatch`, `persist`, `staging`, `ransomware`, ... | Broad, Windows-coupled |
| Deception | `decoys.py`, `embedtokens.py`, `lures.py`, `honeytokens.py` | Strong differentiator |
| Alerting | `alerts.py` (TG/Discord/Slack/SMTP, night mode, batching, digest), `siem.py`, `geolocate.py` | Feature-rich |
| Control | `webapp.py` (Flask), `guardapp.py` (Tk), `tgbot.py` + `cgctl.py` (supervisor), `tamper-check.ps1` | Resilience designed-in |

**Strengths**
- Defense in depth with a clean split: sensors → SQLite (WAL) → alerts/SIEM → control plane.
- The **separate always-on Telegram supervisor** (`cgctl.py`) is genuinely good design — `/start` survives a full service stop.
- Deception depth (decoy files, LSB/zero-width embedded tokens, lures, beaconing) is beyond what most open-source honeypots ship.
- Real operational documentation (troubleshooting table, stop semantics, watchdog cooldowns) — rare for a personal project.
- Pragmatic tech: pure stdlib + 2 deps, single-file SQLite, no heavy infra.

**Weaknesses (summary)** — no tests/CI, machine-specific hardcoded paths, a few correctness bugs,
plaintext secrets at rest, and a lot of "print() as logging". Details below.

---

## 2. Bugs & risks found (concrete, from reading the code)

### Correctness
1. **Local vs UTC time mismatch** — `events.ts` is stored using local time (`datetime.now()` / OpenCanary
   `local_time`), but every SQL filter uses SQLite `datetime('now', ...)` which is **UTC**
   (`logstore.py` — 7 occurrences: `counts_by_category`, `counts_by_severity`, `top_ips`, `failed_logins`,
   …) and `evidence.py` purges with `ts < datetime('now', '-90 days')`.
   In Morocco (UTC+1) all "last 24h" stats/digests are skewed by an hour and boundary cases leak.
   **Fix:** store UTC everywhere (or use `datetime('now','localtime')` consistently).
2. **Log rotation can stall ingestion forever** — `ingest._load_state()` restores a saved offset; after
   log rotation the file is smaller than the offset, `seek()` never errors, `readline()` returns `""`
   forever → the tail silently dies until a restart. **Fix:** detect truncation/rotation (compare
   `os.path.getsize()` with offset, or track inode/mtime) and reset to 0.
3. **Dead code paths** — `classifier.classify()` always returns `honeytoken_hit=False` (never set anywhere);
   `main.py` defines `BASE` and never uses it; `wifiwatch.py`, `phoneglow.py`, `fortress.py` are imported
   nowhere (candidates for wiring-in or removal).

### Reliability / storage
4. **Commit-per-insert** — every `LogStore` insert does `self._conn.commit()` under one lock. Under a scan
   burst (hundreds of events/min) this serialises the whole stack and bloats the WAL.
   **Fix:** batch commits (per ingest cycle / 250ms flush) or a small write-behind buffer.
5. **Unbounded SIEM queue** — `siem.py` `self._queue` is a plain list appended without bound; if Elastic/
   Splunk/HTTP is down for hours, memory grows without limit. No retry, no dead-letter, no TLS-verify
   option on ES calls, and **syslog exports raw JSON including captured passwords over plain UDP**.
   **Fix:** bounded `deque(maxlen=…)` + drop-oldest + optional disk spool + `verify=True` + field scrubbing.
6. **No retention for high-volume tables** — `events`, `net_events`, `process_events`, `file_events` grow
   forever (only `held_alerts` and the 90-day evidence purge touch old rows).
   **Fix:** configurable retention job + periodic `VACUUM`/`PRAGMA optimize`.
7. **Log rotation of OpenCanary log itself is unwatched** (see #2) — also worth an explicit max-size note
   for OpenCanary's own logging config.

### Security
8. **Captured secrets stored in plaintext** — `creds.password`, `keystrokes.keys`, `secret_hits.value` sit
   raw in `canaryguard.db`. Anyone who grabs the file gets everything.
   **Fix:** Fernet field-level encryption keyed from a local secret (or Windows DPAPI via `win32crypt`).
9. **Auto-update on every start** — `start-canaryguard.ps1` runs `git pull --ff-only` at every service
   start. Convenient, but it means whatever lands on the remote branch runs with your privileges,
   unreviewed. **Fix:** pin to signed tags + manual upgrade, or an explicit `/update` Telegram command
   with confirmation.
10. **Evidence zip over Telegram** — nightly backup ships a full SQLite copy (keystrokes, creds, sessions)
    through a third-party service. **Fix:** age/gpg-encrypt the archive before upload, or store locally
    and only send a "backup ready" ping.
11. **Dashboard hardening** — session cookie signs with a random key by default (sessions die every restart
    — arguably good, but confusing); password compared in plain config; no CSRF tokens on mutating
    `/api/*` POST endpoints; no `/api/health` minimal endpoint for the watchdog. (`/t/` honeytoken route is
    intentionally auth-exempt — keep it that way, but rate-limit it.)
12. **SIEM/syslog plaintext egress** (see #5) — same data-protection issue as #8, off-box.

### Engineering hygiene
13. **Hardcoded machine-specific paths** — `C:\Users\<user>\...` in `main.py`, `ingest.py`
    (`STATE_FILE`), `honeytokens.py` (`HONEYTOKEN_FILE`), `decoys.py`, `embedtokens.py`,
    `downloads.py`, `protect.py`, `start-canaryguard.ps1`. The repo is not portable; the Pi deployment
    story in the README doesn't match the code. **Fix:** `CANARYGUARD_HOME` env var / config value,
    defaulting to the repo dir.
14. **No tests, no CI, no packaging check** — 7.4k LOC with zero safety net.
15. **`print()` as the logging framework** — no levels, no rotation, no timestamps in most paths.
    **Fix:** `logging` with `RotatingFileHandler`.
16. **No config validation** — a missing/typo'd key fails deep inside a module (`None.split(':')`,
    `float(None)`). **Fix:** validate `config.json` against a schema at startup; fail fast with a clear
    message listing every problem.
17. **Duplicate control surfaces** — `tgbot.py` and `cgctl.py` implement the same command set; they will
    drift. **Fix:** shared command handler module used by both entrypoints.

---

## 3. Algorithms to add (grouped, pure-Python friendly)

### A. Attacker analytics (extends `AttackProfiler` — highest ROI)

**A1. Isolation-Forest-style anomaly scoring over per-IP feature vectors.**
Features: events/5min, brute attempts, unique usernames, distinct services hit, port fan-out,
mean/variance of inter-arrival times, night/day flag. Train a small forest nightly (or use `sklearn`
optionally; a ~60-line pure-Python half-space-trees version works too). Keep the current static score as
a cold-start fallback. *Effort: M.*

**A2. CUSUM / EWMA change-point detection on the global event rate.**
The current `AttackProfiler` window is a fixed 300s — slow-and-low scanners (1 hit per 10 minutes) are
invisible. A cumulative-sum detector on events/minute flags regime shifts regardless of rate. Also catches
DDoS ramps and "quiet after compromise" drops. *Effort: S.*

**A3. Rarity ("surprisingness") scoring.**
Keep an inverse-frequency table of `(service, logtype, path-class)` over a trailing 30-day baseline; rare
combinations get a severity bump at classification time. Cheap, explainable, no ML stack — the classic
honeypot trick. *Effort: S.*

**A4. Credential-graph clustering (botnet detection).**
Build a bipartite graph IPs ↔ (username, password) pairs nightly in SQLite; run label propagation to find
the same credential tried from dozens of IPs = **credential-stuffing botnet**, or the same IP spraying one
password across many usernames = **password spraying**. Output: incident clusters, one alert instead of
500. *Effort: M.*

**A5. Bloom filter of breached passwords.**
Ship a small bloom filter of the top ~100k passwords (from public SecLists/rockyou). If a honeypot login
attempt hits a top-10 password, tag it `cred_spray`; boosts confidence and prioritisation. Local, offline,
no API. *Effort: S.*

**A6. Scanner fingerprinting / returning-attacker match.**
Feature-hash each source: `(ordered unique ports hit, timing profile bucket, UA string if any, cred pairs)`.
Same hash seen ≥2 days apart → "returning attacker" → bump severity, attach prior history. *Effort: M.*

**A7. Periodicity detection on flows (beacon hunting).**
Autocorrelation (or FFT) over inter-connection intervals in `net_events` and on decoy beacon callbacks —
flags C2-style beaconing (60s/300s/3600s heartbeats) that threshold logic never sees. *Effort: M.*

**A8. Markov n-gram model over fake-shell commands.**
Terminal attacks via the fake API/`shell_command` events: a character n-gram model distinguishes
scripted spray (low entropy path) from interactive human takeover; also great for detecting "attacker is
now typing commands" as a high-severity moment. *Effort: M.*

**A9. Kill-chain session reconstruction.**
Correlate all events by `(src_ip, 24h window)` into an **incident object**: recon → exploit attempt →
credential use → exfil attempt, with a timeline. Powers a dashboard "Incidents" view and one consolidated
page per attacker. This is the single most valuable UX upgrade for a honeypot. *Effort: M–L.*

**A10. Active-learning triage loop.**
Add "mark false positive / confirm" buttons in the dashboard → store labeled examples → a tiny logistic
regression re-ranks alert severity for *your* environment. Gets better every week; starts empty.
*Effort: M.*

**A11. Threat-intel priors.**
Daily-join known-bad IP lists (FireHOL level1, blocklists.de, Spamhaus DROP) into `ip_meta`; add the Tor
exit list. Geolocate already caches — just add a `risk` column. Alert text becomes "…also on FireHOL L1".
*Effort: S.*

**A12. Spray detection across services.**
Same `(password)` or `(username)` failing on ≥N distinct services/ports in T minutes → one
`credential_spray` alert + optional auto-block. Catches what per-service thresholds miss. *Effort: S.*

### B. Host-side detection algorithms

**B1. Process parent→child rarity model.** Count observed `(parent → child)` name pairs forever; an unseen
pair (`winword.exe → powershell.exe`, `explorer.exe → rundll32.exe` with odd args) fires instantly. Extremely
effective, pure counting. *Effort: S–M.*
**B2. LOLBin / path reputation scoring** — unsigned binary in `%TEMP%`/`%AppData%` + known-LOLBin name →
score; combined with B1 this is a poor-man's EDR. *Effort: M.*
**B3. Ransomware-entropy tripwire** (upgrade of `ransomware.py`): add **Shannon-entropy sampling** of recently
renamed/modified files — encrypted files read ~8 bits/byte. Fires *before* the 40-files/minute threshold.
Also flag mass extension changes (`*.locked`, `*.crypt`). *Effort: S–M.*
**B4. Learned idle baseline from `theft.py`** — instead of a static idle threshold, keep an hour-of-day
activity histogram per user; alert when activity appears in hours with ~0 historical activity.
*Effort: S.*
**B5. Aho-Corasick multi-pattern matching for `secretscanner.py`** — replaces the per-regex scan with one
pass over the file; add an entropy prefilter to skip obvious non-secret strings. Orders-of-magnitude faster
on large trees. *Effort: S.*

### C. Deception 2.0

**C1. Per-attacker dynamic credentials (canarytokens-style).** The fake web/services issue **unique**
username/password pairs per session/IP; any pair replayed anywhere later = guaranteed-true positive with
attacker fingerprint attached. *Effort: M.*
**C2. Honey-database with realistic data.** Fake Postgres seeded with plausible `users` rows; any
`SELECT … password` is a critical, unambiguous alert and reveals the attacker's tooling (sqlmap UA, timing).
*Effort: M.*
**C3. JS-beacon fake login portal.** Beyond OpenCanary's static HTTP: render a fake VPN/OWA portal whose JS
fingerprints canvas/WebGL/timezone → device-ID. Deanonymises proxies and identifies repeat actors.
*Effort: M.*
**C4. Anti-fingerprinting.** Randomise fake banners, timing jitter, RSA keys per deployment so masscan/nmap
scripts (which detect OpenCanary by default signatures) can't tell it's a canary. This one materially raises
the quality of the data you collect. *Effort: S–M.*
**C5. Per-download invisible tracking in lure docs** — each generated lure gets a unique invisible watermark
(`"0-width"` id in text, unique pixel id in PDF); if it ever appears elsewhere, you know which leak/exfil
path was used. *Effort: S.*

### D. Operations & engineering

**D1. Test suite + CI (pytest → GitHub Actions).** Start with `classifier.py`, `alerts.py` (night-mode math),
`logstore.py` (schema/migrations), `ingest.py` rotation fix. *Effort: M. Highest priority after fixes.*
**D2. Docker + compose** (OpenCanary + CanaryGuard) for Linux/Pi; healthchecks; restart policy.
*Effort: S–M.*
**D3. Structured logging + `/api/health` + Prometheus `/metrics`** (events ingested, alerts sent/failed,
DB size, WAL size, monitor liveness). Your watchdog then reads metrics, not just TCP-connect. *Effort: S.*
**D4. Retention & maintenance job** — purge policy per table (e.g. events 180d, keystrokes 30d, clipboard 30d),
`VACUUM` weekly, `PRAGMA optimize` on close. *Effort: S.*
**D5. Config schema validation** with jsonschema; every error listed at startup. *Effort: S.*
**D6. Path portability** — `CANARYGUARD_HOME`; remove all `C:\Users\<user>` literals. *Effort: S.*
**D7. Telegram inline buttons** — `[Ack] [Mute 1h] [Block IP 24h] [Open incident]` on alert messages;
`tgbot`/`cgctl` handle callback queries. Converts alerts from noise into a one-tap response loop.
*Effort: M.*
**D8. Auto-block with TTL** — firewall block for N hours with auto-unblock (current `ipblocker` is heavier);
appeal via Telegram. *Effort: S.*
**D9. STIX 2.1 / MISP export** of observed IOCs (IPs, cred pairs used, malware-ish paths) — one-click sharing
with your SOC or community feeds. *Effort: M.*
**D10. Incidents dashboard view** (A9) + **attack-map** (geo scatter from `ip_meta`) + CSV/PDF report export.
*Effort: M.*
**D11. PWA install** of the dashboard (manifest + service worker) → "app" on phone without Telegram dependency.
*Effort: S.*
**D12. Playbooks engine (SOAR-lite).** YAML rules: `when: honeytoken_trip OR ransomware:detected → then:
block IP, lock PC, capture webcam, zip evidence, @notify`. Declarative, testable, replaces scattered `if`s.
*Effort: M–L.*
**D13. Encryption at rest** for `creds`/`keystrokes`/`secret_hits` (bug #8). *Effort: S.*
**D14. Flap detection for monitors** — a monitor that crashes/restarts >3×/hour auto-pauses with an alert
(prevents log/alert storms from a buggy sensor). *Effort: S.*

---

## 4. Suggested roadmap

| Phase | Content | Outcome |
|---|---|---|
| **Phase 0 — Stabilise** (fast) | Bugs #1–#4, #13–#16; D4, D5, D6, D13; tests+CI (D1) | Trustworthy foundation |
| **Phase 1 — See clearly** | A2, A3, A4, A5, A9, A11; D3, D7; Incidents view (D10) | Alerts become incidents; noise drops |
| **Phase 2 — Deception that bites** | C1, C2, C4, C5; B3; A6, A8 | Near-zero false positives; attribution |
| **Phase 3 — Platform** | D2, D9, D12, B1–B2, A10 | CanaryGuard → SOC-grade mini-MSSP |

**Top 5 by impact/effort:** A3 (rarity) → A2 (CUSUM) → D13 (encrypt secrets) → A9 (incidents) → D1 (tests/CI).

**Quick wins you can ship in one sitting:** tz fix (`datetime('now','localtime')`), bounded SIEM queue,
rotation guard in `ingest.py`, Fernet for `creds.password`/`keystrokes`, config schema check, retention job.
