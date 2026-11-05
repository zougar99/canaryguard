import os

import pytest

from canaryguard.logstore import LogStore


@pytest.fixture()
def store(tmp_path):
    s = LogStore(str(tmp_path / "test.db"))
    yield s
    s.close()


def test_insert_and_count(store):
    store.insert_event("2026-11-05 10:00:00", 4002, "203.0.113.1", 5555, 22,
                       "brute_force", "high", {"logtype": 4002})
    rows = store.recent_events(10)
    assert len(rows) == 1
    assert rows[0]["src_ip"] == "203.0.113.1"
    cat_rows = store.recent_events(1)
    assert cat_rows[0]["category"] == "brute_force"


def test_creds_encrypted_at_rest_and_decrypt_transparently(store):
    store.insert_cred("198.51.100.4", "admin", "S3cret!", "ssh", 1)
    raw = store.fetchall("SELECT password FROM creds")
    assert raw[0]["password"].startswith("enc:v1:")
    leaked = store.creds_captured(10)
    assert leaked[0]["password"] == "S3cret!"


def test_keystrokes_encrypted_at_rest(store):
    store.insert_keystrokes("notepad", "mysecretpassword")
    raw = store.fetchall("SELECT keys FROM keystrokes")
    assert raw[0]["keys"].startswith("enc:v1:")
    assert store.recent_keystrokes(10)[0]["keys"] == "mysecretpassword"


def test_purge_older_than(store):
    store.insert_event("2000-01-01 00:00:00", 4002, "203.0.113.9", 1, 22,
                       "brute_force", "high", {"logtype": 4002})
    store.insert_event("2999-01-01 00:00:00", 4002, "203.0.113.10", 1, 22,
                       "brute_force", "high", {"logtype": 4002})
    deleted = store.purge_older_than("events", 30)
    assert deleted == 1
    assert store.fetchall("SELECT COUNT(*) AS n FROM events")[0]["n"] == 1
    with pytest.raises(ValueError):
        store.purge_older_than("sqlite_master; DROP TABLE events;--", 30)


def test_proc_pairs_counting(store):
    for _ in range(3):
        store.observe_proc_pair("winword.exe -> powershell.exe")
    count, total = store.observe_proc_pair("winword.exe -> powershell.exe")
    assert count == 4
    assert total == 4


def test_feedback_roundtrip(store):
    store.insert_feedback(1, "brute_force", "fp", "botnet noise")
    store.insert_feedback(2, "brute_force", "tp")
    stats = store.feedback_stats()
    assert stats["total"] == 2
    assert stats["by_label"]["fp"] == 1
