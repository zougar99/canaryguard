from canaryguard.validation import validate_config


def test_empty_config_reports_missing_storage():
    issues = validate_config({})
    assert any("opencanary.log_file" in i for i in issues)
    assert any("opencanary.db_file" in i for i in issues)


def test_valid_minimal_config_passes():
    config = {
        "opencanary": {"log_file": "/var/log/opencanary.log", "db_file": "/data/cg.db"},
        "alerts": {"min_severity": "medium", "night_floor": "high",
                   "night_start": "23:00", "night_end": "07:00", "digest_time": "08:00",
                   "cooldown_seconds": 60, "batch_limit": 3, "batch_window_seconds": 300},
        "dashboard": {"host": "127.0.0.1", "port": 8080, "password": "secret"},
        "telegram_bot": {"owner": "supervisor"},
        "clipboard_monitor": {"mode": "keywords"},
        "ransomware": {"threshold": 40, "window_seconds": 60},
        "ipblock": {"max_fails": 5, "window_seconds": 300, "block_minutes": 60},
        "analytics": {"spray_min_ips": 5, "spray_min_users": 10},
        "playbooks": {"rules": []},
        "retention": {"days": {"events": 180}},
    }
    assert validate_config(config) == []


def test_bad_values_are_flagged():
    config = {
        "opencanary": {"log_file": "/x", "db_file": "/y"},
        "alerts": {"min_severity": "shouty", "night_start": "99:99"},
        "dashboard": {"port": 99999},
        "telegram_bot": {"owner": "nobody"},
        "retention": {"days": {"events": -3}},
    }
    issues = validate_config(config)
    assert any("min_severity" in i for i in issues)
    assert any("port" in i for i in issues)
    assert any("owner" in i for i in issues)
    assert any("retention.days.events" in i for i in issues)
