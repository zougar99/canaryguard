import json

from canaryguard.logstore import LogStore
from canaryguard.stix import export_bundle, bundle_json


def test_stix_bundle_structure(tmp_path):
    db = str(tmp_path / "s.db")
    store = LogStore(db)
    store.insert_event("2026-11-05 10:00:00", 4002, "203.0.113.77", 22222, 22,
                       "brute_force", "critical", {"logtype": 4002})
    bundle = export_bundle(store, hours=24 * 365 * 10)  # generous window for the old ts
    assert bundle["type"] == "bundle"
    types = {obj["type"] for obj in bundle["objects"]}
    assert {"identity", "indicator", "sighting"} <= types
    indicator = next(o for o in bundle["objects"] if o["type"] == "indicator")
    assert "203.0.113.77" in indicator["pattern"]
    parsed = json.loads(bundle_json(store, hours=24 * 365 * 10))
    assert parsed["spec_version"] == "2.1"
    store.close()
