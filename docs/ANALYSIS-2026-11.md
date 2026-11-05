# CanaryGuard — Project Analysis

> Date: 2026-11-05 · Version analysed: **1.1.0** · Scope: full repo @ `arena/74c67d0d-canaryguard`
> (working tree incl. `1a22471`). This document complements `ANALYSIS-AND-ROADMAP.md` (phased
> roadmap + what was implemented) with a current, honest assessment.

## 1. Executive summary

CanaryGuard is a **self-hosted honeypot + host-IDS + remote-control stack** for a single
Windows machine (Linux/Pi honeypot path supported). At v1.1.0 it is: installable (Windows
exes + wheel/sdist on GitHub Release), installable as a browser app (PWA), demo-able in
seconds (`python -m canaryguard.demo`), CI-green (3.11/3.12), and has a real (if young)
analytics engine on top of classic canary alerting.

Honest bottom line: **strong feature breadth, young engineering discipline.** The biggest
risks are (a) single-admin, no-roles security model, (b) host-side sensor code that has
never run on Linux CI (Windows-only), (c) test coverage concentrated on analytics/demo
paths while host-side sensors, web routes and protocols have none, (d) packaging that was
only recently automated — the Windows installer has never compiled anywhere yet.

## 2. Inventory & size

| Metric | Value |
|---|---|
| Python LOC | ~12,400 (58 source modules, 14 test modules) |
| Other | HTML 499 · JS 58 · PS 294 · SH 110 · YML 144 · INNO 65 · MD 976 · JSON 314 |
| Tests | **55** (`python -m pytest tests/`) — all green locally & CI (3.11/3.12) |
| Web routes | 47 (`webapp.py`, 620 LOC) |
| Largest modules | protocols.py 838 · logstore.py 789 · webapp.py 620 · embedtokens.py 416 · decoys.py 375 |
| Distribution | GitHub Release v1.1.0: `CanaryGuard.exe`, `CanaryGuardApp.exe`, wheel, sdist |
| Infra | Dockerfile + compose · CI (`ci.yml`, 3.11/3.12) · Release (`release.yml`, tag `v*`) |

## 3. Architecture assessment

Five layers, all present: **honeypot** (`protocols.py` 15+ fake services, `ingest.py`,
`classifier.py`) → **host sensors** (procs, usbdisk, netmon, sessions, keylogger, …) →
**deception** (decoys, embedtokens, lures, honey tokens) → **alerting** (Telegram/Discord/
Slack/SMTP, night mode, batching, digest, SIEM forwarder) → **control** (Flask dashboard
+ Tk desktop app + `cgctl.py` Telegram supervisor + watchdog).

Strengths: clear layering; state anchored to one home dir (`paths.home`, `CANARYGUARD_HOME`);
at-rest Fernet for captured creds/keystrokes/secrets (`cryptostore.py`, legacy migration);
at-least-once event intake with rotation/truncation handling (`ingest.py`); kill-chain
incident reconstruction with MITRE labels (`incidents.py`, `/api/incidents`); STIX 2.1 export;
SOAR-lite playbooks; watermarked lure docs; CUSUM change-point on the event rate;
spray/anomaly engines with monotonic-clock-safe cooldowns (a real bug class found & fixed
across 14 call sites this cycle).

Weaknesses: `webapp.py` is a 620-line god-object wiring 47 routes; `logstore.py` (789 LOC)
carries all SQL; protocols are untested and Windows-coupled; telemetry UI in the dashboard
is endpoints-only (no analytics tab).

## 4. Security assessment

### 4.1 Fixed in this analysis round (commit `1a22471`)

**Remote shell-interpolation injection (the headline finding).** Several `os.system` calls
interpolated values that originate from the network or HTTP:

- `ipblocker.register_fail/_block/cleanup`: `netsh ... remoteip={ip}` with `ip` straight
  from ingested events; the firewall rule name too. A crafted `src_host` containing
  `; cmd` would have executed on the host as the CanaryGuard service (SYSTEM/admin).
- `webapp /api/ipblock/remove`: `ip` from the JSON body into the same netsh command
  (double-quote break-out), reachable by the admin role.
- `fortress.py` / `ransomware.py`: `network_adapter` from config into `netsh` via
  double-quoted f-strings.

All now whitelisted: IPs via `ipaddress.ip_address()` (canonical form), adapter via
`^[A-Za-z0-9 _-]{1,64}$`; invalid input is dropped/disabled with a log line. Session
cookie now explicitly `HttpOnly` + `SameSite=Lax`. Regression tests in
`tests/test_ipblocker.py` (55 tests green). **Note:** the same fix must be re-applied if
new `os.system`/netsh sites are added — the codebase has no sandbox for the shell.

### 4.2 Confirmed good

- **No SQL string-built queries** (0 hits for `execute(f"…`, all parameterized).
- **0 bare `except:`**; 210 broad `except Exception` (see 4.4).
- SIEM forwarder: timeouts (10s), TLS verification, bounded drop-oldest queue, secret
  scrubbing (`siem.py`). Web dashboard requires auth (or local-only); all actions behind
  the session; login failures feed panic lockout.
- Evidence zips support optional user-held encryption key.

### 4.3 Open / by-design, must understand before deploying

1. **Single admin, no roles.** `dashboard.username/password` — whoever is admin can lock,
   panic, block, exfiltrate the keylogger buffer. There is no read-only viewer role.
   `setup_admin.py` exists for bootstrap/reset — use it.
2. **No CSRF tokens.** State-changing POSTs rely on `SameSite=Lax` + JSON content-type.
   Acceptable for a LAN/tailnet tool, not for exposure to the open internet.
3. **Plaintext password in config.json** (required for dashboard auth) — file perms matter;
   `secret.key` is gitignored; at-rest data is Fernet-encrypted but creds fall back to
   plaintext **silently** if `cryptography` is missing (import-time warning only — consider
   hard-failing in production).
4. **Demo mode ships `noauth_allow_remote: true`** — intentional, fake data, never reuse.
5. **Flask dev server** serves the dashboard (`app.run`); put it behind a real WSGI/reverse
   proxy for anything beyond trusted nets.
6. **No login rate-limit** beyond the panic counter; `/login` should get a simple delay/limit.
7. **Operational scripts** (`*.ps1`) still run elevated context with broad rights by design —
   review before reuse.

### 4.4 Maintainability: 210 broad `except Exception`

Mostly deliberate (a sensor must not kill the watchdog). But it also swallows programming
errors silently. Recommendation: log-and-count, and alert on repeated failures per module
(you already have the alert pipe).

### 4.5 XSS surface (dashboard)

All dynamic `innerHTML` interpolations pass through `esc()` (verified spot-check of render
functions; only numeric/enum-like values bypass it). Risk is low; `sevBadge()` emits trusted
internal HTML. Keep the `esc()` discipline — the rule that saves you is *esc() everything
that came from the DB*.

## 5. Quality & testing

- **Strengths:** analytics engine well-covered (changepoint, spray, rarity, markov,
  commonpass, credgraph, incidents, beacon), logstore, ingest rotation, cryptostore,
  maintenance, validation, playbooks, STIX, demo seeding, setup_admin, ipblocker.
- **Gaps (none of these have tests):** `webapp` (47 routes!), `protocols` (838 LOC),
  `embedtokens`, `decoys`, `keylogger`, `sessions`, `usbdisk`, `netmon`, `staging`,
  `fortress`, `panic`, `control`, `tgbot`, `luredoc`, `processgraph`, all `*watch`
  modules. Host-side sensors cannot be exercised in Linux CI (Windows-only, admin,
  interactive Session-0 issues).
- No linter/formatter/typecheck in CI; no coverage reporting; no property/fuzz tests.

## 6. Packaging & release

- Release **v1.1.0** published: Windows exes (PyInstaller), wheel, sdist. **The Inno Setup
  installer has never compiled** — runner had no Inno Setup; CI step now installs it via
  choco for future tags (`v1.1.1`), and `packaging/windows/` ships locally-buildable .iss.
- Docker image **never built** here; `docker-compose.yml` unverified.
- PWA (manifest + SW + icons) verified server-side only; not exercised on a real device/HTTPS.
- CI green on 3.11/3.12 via `workflow_dispatch`; the old red PR check was the monotonic
  cooldown bug (now fixed) — fresh runners boot with uptime≈0, so `.get(key, 0)` meant
  "on cooldown since boot".

## 7. Risk register (top 10)

| # | Risk | Sev | Likelihood | Status |
|---|---|---|---|---|
| R1 | Shell interpolation of network/admin input → RCE | Critical | was real | **Fixed `1a22471`** |
| R2 | Demo/noauth config leaked to production | High | medium | Documented; demo isolated |
| R3 | Untested web routes incl. actions (lock/panic/block) | High | medium | Open — needs route tests |
| R4 | Windows-only sensors crash on Linux/Pi path | High | medium | Open — guard + smoke tests |
| R5 | At-rest encryption silently degrades w/o `cryptography` | Medium | low | Open — hard-fail option |
| R6 | No roles; one password = full control | Medium | — | By design; documented |
| R7 | Plaintext dashboard password in config.json | Medium | local file | Perms + setup_admin |
| R8 | Flask dev server / no reverse proxy | Medium | — | Docs; compose needs override |
| R9 | Silent failure via broad `except` | Low/Med | high | Open — add metrics |
| R10 | Untested installer/.iss pipeline | Medium | — | Next tag builds it via choco |

## 8. Prioritised recommendations

**P0** — Test the 10 security-relevant web routes (`/api/ipblock/remove`, login lockout,
panic, lock, keylogger read, sessions, embedtokens trigger). Add `webapp` test client
fixture. Add `--require-encryption` startup flag (fail-fast if `cryptography` missing).
**P1** — CSRF token for state-changing routes or enforce `Sec-Fetch-Site: same-origin`.
`Secure` cookie behind TLS proxy config. Docker build + compose smoke in CI. Route auth
coverage test enumerating all 47 routes and asserting 401/redirect unauthenticated.
**P2** — Analytics tab in the dashboard (endpoints already exist). Playbook dry-run mode.
Metrics endpoint + uptime heartbeat. Property tests for the changepoint detector. Pin CI
toolchain (pip-compile / constraints).

## 9. Methodology & limitations

Static analysis by hand + grep/AST-flavored scans (SQL f-strings, bare excepts, shell calls,
XSS esc discipline); test suite 55/55; git history review; CI/release inspection via GitHub
API. No live penetration test, no fuzzing, no static analyzer (bandit/semgrep) — recommend
adding both to CI. CI logs unreachable from this environment (network); CI status read from
the API only. Numbers are point-in-time and approximate (LOC counts include demo/tests where
noted).

*This analysis was written 2026-11-05 and reflects the repository at `1a22471`.*
