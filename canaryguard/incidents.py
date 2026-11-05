"""Kill-chain incident reconstruction — A9 from the roadmap.

Groups events per source IP over a window and maps them onto a simplified
attack chain: recon -> exploitation -> credential access -> exfiltration ->
impact. Each group becomes an "incident" with a timeline, severity and
MITRE-ish labels. This is what turns 400 raw rows into one actionable page.
"""

import hashlib
from datetime import datetime, timedelta

STAGE_RECON = "recon"
STAGE_EXPLOIT = "exploitation"
STAGE_CREDS = "credential_access"
STAGE_EXFIL = "exfiltration"
STAGE_IMPACT = "impact"

STAGE_ORDER = [STAGE_RECON, STAGE_EXPLOIT, STAGE_CREDS, STAGE_EXFIL, STAGE_IMPACT]

MITRE = {
    STAGE_RECON: "T1046 Network Service Discovery",
    STAGE_EXPLOIT: "T1190 Exploit Public-Facing Application",
    STAGE_CREDS: "T1110 Brute Force",
    STAGE_EXFIL: "T1560 Archive Collected Data",
    STAGE_IMPACT: "T1486 Data Encrypted for Impact",
}

_CATEGORY_STAGE = {
    "recon": STAGE_RECON,
    "port_scan": STAGE_RECON,
    "http_probe": STAGE_RECON,
    "sensitive_access": STAGE_RECON,
    "mail_scanner": STAGE_RECON,
    "voip_scan": STAGE_RECON,
    "camera_scan": STAGE_RECON,
    "ics_probe": STAGE_RECON,
    "iot_probe": STAGE_RECON,
    "remote_access_probe": STAGE_RECON,
    "directory_probe": STAGE_RECON,
    "java_exploit_probe": STAGE_RECON,
    "api_probe": STAGE_RECON,
    "exploit_attempt": STAGE_EXPLOIT,
    "api_exploit_attempt": STAGE_EXPLOIT,
    "web_login_attack": STAGE_EXPLOIT,
    "shell_command": STAGE_EXPLOIT,
    "database_attack": STAGE_EXPLOIT,
    "brute_force": STAGE_CREDS,
    "credential_spray": STAGE_CREDS,
    "file_exfil_attempt": STAGE_EXFIL,
    "staging:archive": STAGE_EXFIL,
    "staging_archive": STAGE_EXFIL,
    "ransomware:detected": STAGE_IMPACT,
    "theft:alarm": STAGE_IMPACT,
}

_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _stage_for(category):
    if not category:
        return None
    return _CATEGORY_STAGE.get(category) or _CATEGORY_STAGE.get(str(category).lower())


def _max_severity(sevs):
    best = "info"
    for s in sevs:
        if _SEV_RANK.get(s or "info", 0) > _SEV_RANK.get(best, 0):
            best = s
    return best


def build_incidents(store, hours=24, min_events=2, limit_ips=50):
    """Return a list of incident dicts sorted by (stage depth, severity)."""
    since = (datetime.now() - timedelta(hours=int(hours))).strftime("%Y-%m-%d %H:%M:%S")
    rows = store.fetchall(
        "SELECT src_ip, category, severity, dst_port, ts "
        "FROM events WHERE ts >= ? AND src_ip IS NOT NULL AND src_ip != '' "
        "ORDER BY src_ip, ts",
        (since,),
    )
    by_ip = {}
    for row in rows:
        by_ip.setdefault(row["src_ip"], []).append(row)

    incidents = []
    for ip, evs in by_ip.items():
        if len(evs) < min_events:
            continue
        stages = []
        for ev in evs:
            stage = _stage_for(ev.get("category"))
            if stage and stage not in stages:
                stages.append(stage)
        stages.sort(key=lambda s: STAGE_ORDER.index(s))
        categories = sorted({(e.get("category") or "unknown") for e in evs})
        ports = sorted({str(e.get("dst_port")) for e in evs if e.get("dst_port") is not None},
                       key=lambda p: int(p) if p.isdigit() else 0)
        severity = _max_severity([e.get("severity") for e in evs])
        meta = store.ip_meta(ip) if hasattr(store, "ip_meta") else None
        window = f"{evs[0]['ts']}..{evs[-1]['ts']}"
        incident_id = hashlib.sha256(f"{ip}|{window}".encode()).hexdigest()[:12]
        incidents.append({
            "id": incident_id,
            "src_ip": ip,
            "country": (meta or {}).get("country", ""),
            "city": (meta or {}).get("city", ""),
            "org": (meta or {}).get("org", ""),
            "first_seen": evs[0]["ts"],
            "last_seen": evs[-1]["ts"],
            "event_count": len(evs),
            "max_severity": severity,
            "stages": stages,
            "kill_chain": [MITRE[s] for s in stages],
            "categories": categories,
            "ports": ports,
            "depth": len(stages),
        })
    incidents.sort(key=lambda i: (i["depth"], _SEV_RANK.get(i["max_severity"], 0), i["event_count"]), reverse=True)
    return incidents[: int(limit_ips)]


def incident_timeline(store, src_ip, hours=24, limit=200):
    since = (datetime.now() - timedelta(hours=int(hours))).strftime("%Y-%m-%d %H:%M:%S")
    rows = store.fetchall(
        "SELECT ts, category, severity, dst_port, raw_json FROM events "
        "WHERE src_ip=? AND ts >= ? ORDER BY ts DESC LIMIT ?",
        (src_ip, since, int(limit)),
    )
    for row in rows:
        stage = _stage_for(row.get("category"))
        row["stage"] = stage
        row["mitre"] = MITRE.get(stage, "")
    return rows
