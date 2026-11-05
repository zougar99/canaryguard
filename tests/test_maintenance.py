from canaryguard.logstore import LogStore
from canaryguard.maintenance import RetentionJob


class _FakeConfig:
    def __init__(self, data):
        self.data = data

    def section(self, name, *args, **kwargs):
        return self.data.get(name, {})

    def get(self, *keys, default=None):
        node = self.data
        for key in keys:
            node = node.get(key, default) if isinstance(node, dict) else default
        return node


def test_retention_purges_old_rows(tmp_path):
    db = str(tmp_path / "m.db")
    store = LogStore(db)
    store.insert_event("2000-01-01 00:00:00", 4002, "203.0.113.1", 1, 22,
                       "brute_force", "high", {"logtype": 4002})
    store.insert_event("2999-01-01 00:00:00", 4002, "203.0.113.2", 1, 22,
                       "brute_force", "high", {"logtype": 4002})
    cfg = _FakeConfig({"retention": {"enabled": True, "days": {"events": 30}}})
    job = RetentionJob(cfg, store=store, logger=lambda *a: None)
    deleted = job.run_once()
    assert deleted >= 1
    assert store.fetchall("SELECT COUNT(*) AS n FROM events")[0]["n"] == 1
    store.close()


def test_retention_zero_disables_table(tmp_path):
    db = str(tmp_path / "m2.db")
    store = LogStore(db)
    store.insert_event("2000-01-01 00:00:00", 4002, "203.0.113.1", 1, 22,
                       "brute_force", "high", {"logtype": 4002})
    cfg = _FakeConfig({"retention": {"enabled": True, "days": {"events": 0}}})
    job = RetentionJob(cfg, store=store, logger=lambda *a: None)
    assert job.run_once() == 0
    store.close()
