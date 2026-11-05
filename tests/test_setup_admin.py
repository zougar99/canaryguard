import json

from canaryguard import setup_admin


def test_generate_creates_strong_password_and_sets_keys(tmp_path):
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({"dashboard": {}}), encoding="utf-8")
    rc = setup_admin.main(["--config", str(cfg), "--generate"])
    assert rc == 0
    data = json.loads(cfg.read_text(encoding="utf-8"))
    assert data["dashboard"]["username"] == "admin"
    assert len(data["dashboard"]["password"]) >= 12
    assert data["dashboard"]["secret_key"]
    assert (tmp_path / "config.json.bak").exists()


def test_short_password_refused_without_force(tmp_path):
    cfg = tmp_path / "config.json"
    cfg.write_text("{}", encoding="utf-8")
    assert setup_admin.main(["--config", str(cfg), "--password", "short"]) == 2
    assert setup_admin.main(["--config", str(cfg), "--password", "short", "--force"]) == 0
