import os

from canaryguard import demo
from canaryguard.logstore import LogStore


def test_seed_creates_believable_history(tmp_path):
    home = tmp_path / "home"
    db = tmp_path / "demo.db"
    demo.seed(home=str(home), db_path=str(db), seed_value=7)

    store = LogStore(str(db))
    assert store.fetchall("SELECT COUNT(*) AS n FROM events")[0]["n"] > 100
    assert store.fetchall("SELECT COUNT(*) AS n FROM creds")[0]["n"] > 0
    assert store.fetchall("SELECT COUNT(*) AS n FROM net_events")[0]["n"] == 48
    # the full-chain attacker must reconstruct a deep incident
    from canaryguard.incidents import build_incidents

    incidents = build_incidents(store, hours=24 * 365 * 10, min_events=3)
    top = incidents[0]
    assert top["depth"] >= 3
    assert top["max_severity"] == "critical"
    store.close()


def test_config_written_is_valid_json(tmp_path):
    import json

    home = tmp_path / "home"
    db = tmp_path / "demo.db"
    cfg_path = demo.write_config(home=str(home), db_path=str(db), port=8099)
    data = json.load(open(cfg_path, encoding="utf-8"))
    assert data["dashboard"]["port"] == 8099
    # demo-only: no auth — the whole point is zero-friction local preview
    assert data["dashboard"]["noauth_allow_remote"] is True
