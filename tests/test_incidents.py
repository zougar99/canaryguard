from canaryguard.incidents import build_incidents, incident_timeline
from canaryguard.logstore import LogStore


def test_incident_reconstruction(tmp_path):
    db = str(tmp_path / "i.db")
    store = LogStore(db)
    ip = "203.0.113.200"
    store.insert_event("2026-11-05 10:00:00", 3000, ip, 4444, 80, "recon", "low", {"PATH": "/"})
    store.insert_event("2026-11-05 10:01:00", 3001, ip, 4444, 80, "web_login_attack", "high", {"PATH": "/login"})
    store.insert_event("2026-11-05 10:02:00", 4002, ip, 4444, 22, "brute_force", "critical", {})
    incidents = build_incidents(store, hours=24 * 365 * 10, min_events=2)
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc["src_ip"] == ip
    assert inc["stages"] == ["recon", "exploitation", "credential_access"]
    assert inc["depth"] == 3
    assert inc["max_severity"] == "critical"
    assert any("T1110" in m for m in inc["kill_chain"])
    timeline = incident_timeline(store, ip, hours=24 * 365 * 10)
    assert len(timeline) == 3
    assert all("stage" in row for row in timeline)
    store.close()


def test_minor_sources_are_filtered(tmp_path):
    db = str(tmp_path / "i2.db")
    store = LogStore(db)
    store.insert_event("2026-11-05 10:00:00", 3000, "203.0.113.201", 1, 80, "recon", "low", {})
    assert build_incidents(store, hours=24 * 365 * 10, min_events=2) == []
    store.close()
