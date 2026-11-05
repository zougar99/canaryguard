import canaryguard.ipblocker as ipb


class _Cfg:
    def __init__(self, db):
        self.data = {
            "opencanary": {"db_file": str(db)},
            "ipblock": {"enabled": True, "max_fails": 2, "window_seconds": 300, "block_minutes": 60},
        }

    def get(self, *keys, default=None):
        node = self.data
        for k in keys:
            if not isinstance(node, dict) or k not in node:
                return default
            node = node[k]
        return node

    def section(self, *keys, **kwargs):
        node = self.data
        for k in keys:
            node = node.get(k, {}) if isinstance(node, dict) else {}
        return node if isinstance(node, dict) else {}


def test_valid_ip_accepts_and_rejects():
    assert ipb.valid_ip("192.0.2.1") == "192.0.2.1"
    assert ipb.valid_ip("2001:db8::1") == "2001:db8::1"
    for bad in ["", "?", "1.2.3.4; calc.exe", "$(calc)", "999.0.0.1", "a&b",
                'x" & echo pwned', "1.2.3.4/24", "-remoteip=1.2.3.4"]:
        assert ipb.valid_ip(bad) is None, bad


def test_malicious_source_never_reaches_shell(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(ipb.os, "system", lambda cmd: calls.append(cmd) or 1)
    blocker = ipb.IPBlocker(_Cfg(tmp_path / "t.db"), alerts=None, logger=lambda *a: None)
    for bad in ["1.2.3.4; calc.exe", "1.2.3.4 & netsh", "$(touch /tmp/pwned)", "10.0.0.1|whoami"]:
        for _ in range(5):
            blocker.register_fail(bad)
    assert calls == []


def test_legitimate_ip_blocked_after_threshold(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(ipb.os, "system", lambda cmd: calls.append(cmd) or 0)
    blocker = ipb.IPBlocker(_Cfg(tmp_path / "t.db"), alerts=None, logger=lambda *a: None)
    blocker.register_fail("198.51.100.7")
    blocker.register_fail("198.51.100.7")
    assert any("remoteip=198.51.100.7" in c for c in calls)
    assert any("CanaryBlock_198_51_100_7" in c for c in calls)
