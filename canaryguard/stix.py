"""STIX 2.1 export — D9 from the roadmap.

Hand-built STIX bundles (no stix2 dependency): one ipv4-addr indicator per
source IP seen with high/critical severity, plus sightings. Valid enough for
paste into OpenCTI / MISP.
"""

import json
import uuid
from datetime import datetime, timedelta

_NAMESPACE = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")


def _id(prefix, value):
    return f"{prefix}--{uuid.uuid5(_NAMESPACE, value)}"


def _now():
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")


def export_bundle(store, hours=24):
    since = (datetime.now() - timedelta(hours=int(hours))).strftime("%Y-%m-%d %H:%M:%S")
    rows = store.fetchall(
        "SELECT src_ip, COUNT(*) AS n, MAX(severity) AS sev, MAX(ts) AS last_seen "
        "FROM events WHERE ts >= ? AND src_ip IS NOT NULL AND src_ip != '' "
        "AND severity IN ('high','critical') "
        "GROUP BY src_ip ORDER BY n DESC LIMIT 500",
        (since,),
    )
    objects = []
    identity_id = _id("identity", "canaryguard-local-instance")
    objects.append({
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": _now(),
        "modified": _now(),
        "name": "CanaryGuard (local)",
        "identity_class": "system",
    })
    for row in rows:
        ip = row["src_ip"]
        ind_id = _id("indicator", ip)
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": ind_id,
            "created": _now(),
            "modified": _now(),
            "name": f"CanaryGuard observed attacker {ip}",
            "description": f"{row['n']} high/critical events in last {hours}h (peak severity {row['sev']})",
            "pattern": f"[ipv4-addr:value = '{ip}']",
            "pattern_type": "stix",
            "valid_from": _now(),
            "indicator_types": ["malicious-activity"],
            "created_by_ref": identity_id,
        })
        objects.append({
            "type": "sighting",
            "spec_version": "2.1",
            "id": _id("sighting", f"{ip}|{row['last_seen']}"),
            "created": _now(),
            "modified": _now(),
            "sighting_of_ref": ind_id,
            "count": int(row["n"]),
            "first_seen": _now(),
            "last_seen": _now(),
            "created_by_ref": identity_id,
        })
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "objects": objects,
    }


def bundle_json(store, hours=24):
    return json.dumps(export_bundle(store, hours=hours), ensure_ascii=False, indent=2)
