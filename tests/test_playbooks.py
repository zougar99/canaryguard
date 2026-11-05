from canaryguard.playbooks import PlaybookEngine


class _FakeConfig:
    def __init__(self, data):
        self.data = data

    def section(self, *keys):
        node = self.data
        for key in keys:
            node = node.get(key, {}) if isinstance(node, dict) else {}
        return node if isinstance(node, dict) else {}


class _FakeBlocker:
    def __init__(self):
        self.blocked = []

    def _block(self, ip, fails=1):
        self.blocked.append((ip, fails))


def _engine(rules, enabled=True, blocker=None):
    cfg = _FakeConfig({"playbooks": {"enabled": enabled, "rules": rules}})
    return PlaybookEngine(cfg, store=None, alerts=None, ipblock=blocker, logger=lambda *a: None)


RULE = {
    "name": "spray-lockdown",
    "when": {"category": ["credential_spray"], "severity_gte": "high", "cooldown_minutes": 60},
    "then": [{"action": "block_ip", "minutes": 30}],
}


def test_rule_blocks_ip_on_match():
    blocker = _FakeBlocker()
    engine = _engine([RULE], blocker=blocker)
    # store is only used for get_store fallback; disabled lookups are fine here
    engine.store = None
    executed = engine.evaluate({"src_ip": "203.0.113.50", "src_host": "203.0.113.50"},
                               "credential_spray", "high", "test")
    assert blocker.blocked == [("203.0.113.50", 99)]
    assert any("block_ip" in e for e in executed)


def test_rule_skips_below_floor():
    blocker = _FakeBlocker()
    engine = _engine([RULE], blocker=blocker)
    engine.store = None
    engine.evaluate({"src_ip": "203.0.113.50"}, "credential_spray", "medium", "")
    assert blocker.blocked == []


def test_disabled_engine_does_nothing():
    blocker = _FakeBlocker()
    engine = _engine([RULE], enabled=False, blocker=blocker)
    engine.store = None
    assert engine.evaluate({"src_ip": "203.0.113.50"}, "credential_spray", "high", "") == []
    assert blocker.blocked == []


def test_unknown_action_is_skipped():
    engine = _engine([{"name": "x", "when": {"category": ["brute_force"]},
                       "then": [{"action": "self_destruct"}]}])
    engine.store = None
    executed = engine.evaluate({"src_ip": "203.0.113.1"}, "brute_force", "high", "")
    assert executed == []
