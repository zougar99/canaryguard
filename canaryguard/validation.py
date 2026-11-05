"""Config validation — D5 from the roadmap.

A cheap, dependency-free sanity check run at startup. Collects every issue
it can find so you fix config.json in one pass instead of whack-a-mole
AttributeErrors deep in the sensors.
"""

_SEVERITIES = {"info", "low", "medium", "high", "critical"}
_OWNERS = {"supervisor", "main"}
_MODES = {"keywords", "all"}


def validate_config(data):
    issues = []
    if not isinstance(data, dict):
        return ["config root must be a JSON object"]

    def section(name):
        sec = data.get(name, {})
        if sec is None:
            return {}
        if not isinstance(sec, dict):
            issues.append(f"section '{name}' must be an object")
            return {}
        return sec

    def check_int(sec, key, lo, hi, name):
        v = sec.get(key)
        if v is None:
            return
        if not isinstance(v, (int, float)) or isinstance(v, bool):
            issues.append(f"{name}.{key} must be a number, got {v!r}")
            return
        if not (lo <= v <= hi):
            issues.append(f"{name}.{key}={v} out of range [{lo}, {hi}]")

    oc = section("opencanary")
    if not oc.get("log_file"):
        issues.append("opencanary.log_file is not set — ingest has nothing to tail")
    if not oc.get("db_file"):
        issues.append("opencanary.db_file is not set — no storage configured")

    alerts = section("alerts")
    sev = alerts.get("min_severity")
    if sev is not None and sev not in _SEVERITIES:
        issues.append(f"alerts.min_severity must be one of {sorted(_SEVERITIES)}, got {sev!r}")
    floor = alerts.get("night_floor")
    if floor is not None and floor not in _SEVERITIES:
        issues.append(f"alerts.night_floor must be one of {sorted(_SEVERITIES)}, got {floor!r}")
    check_int(alerts, "cooldown_seconds", 0, 86400, "alerts")
    check_int(alerts, "batch_limit", 1, 1000, "alerts")
    check_int(alerts, "batch_window_seconds", 1, 86400, "alerts")
    for key in ("night_start", "night_end", "digest_time"):
        v = alerts.get(key)
        if v is not None:
            parts = str(v).split(":")
            if len(parts) != 2 or not all(p.isdigit() and 0 <= int(p) <= 59 or p == parts[0] and 0 <= int(p) <= 23 for p in parts):
                try:
                    h, m = int(parts[0]), int(parts[1])
                    if not (0 <= h <= 23 and 0 <= m <= 59):
                        raise ValueError
                except Exception:
                    issues.append(f"alerts.{key} must be 'HH:MM', got {v!r}")

    dash = section("dashboard")
    check_int(dash, "port", 1, 65535, "dashboard")
    if not dash.get("password") and not dash.get("noauth_allow_remote"):
        trusted = dash.get("trusted_networks") or []
        if dash.get("host") not in ("127.0.0.1", "localhost", None) and not trusted:
            issues.append("dashboard binds beyond localhost with no password and no trusted_networks — will serve 403, did you mean to set a password?")

    bot = section("telegram_bot")
    owner = bot.get("owner")
    if owner is not None and str(owner).lower() not in _OWNERS:
        issues.append(f"telegram_bot.owner must be one of {sorted(_OWNERS)}, got {owner!r}")

    clip = section("clipboard_monitor")
    mode = clip.get("mode")
    if mode is not None and mode not in _MODES:
        issues.append(f"clipboard_monitor.mode must be one of {sorted(_MODES)}, got {mode!r}")

    ransomware = section("ransomware")
    check_int(ransomware, "threshold", 1, 100000, "ransomware")
    check_int(ransomware, "window_seconds", 1, 86400, "ransomware")

    ipblock = section("ipblock")
    check_int(ipblock, "max_fails", 1, 10000, "ipblock")
    check_int(ipblock, "window_seconds", 1, 86400, "ipblock")
    check_int(ipblock, "block_minutes", 1, 100000, "ipblock")

    analytics = section("analytics")
    check_int(analytics, "spray_min_ips", 2, 10000, "analytics")
    check_int(analytics, "spray_min_users", 2, 10000, "analytics")

    playbooks = section("playbooks")
    rules = playbooks.get("rules", [])
    if rules is not None and not isinstance(rules, list):
        issues.append("playbooks.rules must be a list")

    retention = section("retention")
    days = retention.get("days", {})
    if days is not None:
        if not isinstance(days, dict):
            issues.append("retention.days must be an object mapping table -> days")
        else:
            for k, v in days.items():
                if not isinstance(v, (int, float)) or v < 0:
                    issues.append(f"retention.days.{k} must be a non-negative number, got {v!r}")

    return issues
