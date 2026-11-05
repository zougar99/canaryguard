from canaryguard.alerts import AlertManager


class _FakeConfig:
    def __init__(self, data):
        self.data = data

    def section(self, *keys):
        node = self.data
        for key in keys:
            node = node.get(key, {}) if isinstance(node, dict) else {}
        return node if isinstance(node, dict) else {}

    def get(self, *keys, default=None):
        node = self.data
        for key in keys:
            node = node.get(key, default) if isinstance(node, dict) else default
        return node


def _alerts(inline):
    cfg = {"alerts": {"enabled": True, "inline_buttons": inline, "telegram": {"enabled": False}}}
    am = AlertManager.__new__(AlertManager)
    am.config = _FakeConfig(cfg)
    am.inline_buttons = inline
    return am


def test_buttons_on_critical_with_ip():
    am = _alerts(True)
    buttons = am._buttons_for("brute_force", "203.0.113.9", "critical")
    assert buttons is not None
    flat = [btn for row in buttons["inline_keyboard"] for btn in row]
    data = {b["callback_data"] for b in flat}
    assert "ack" in data
    assert "mute:brute_force" in data
    assert "block:203.0.113.9" in data


def test_no_block_button_for_local_source():
    am = _alerts(True)
    buttons = am._buttons_for("usb:connect", "127.0.0.1", "high")
    flat = [btn for row in buttons["inline_keyboard"] for btn in row]
    assert all(not b["callback_data"].startswith("block:") for b in flat)


def test_buttons_disabled_and_low_severity():
    am = _alerts(False)
    assert am._buttons_for("brute_force", "203.0.113.9", "critical") is None
    am = _alerts(True)
    assert am._buttons_for("brute_force", "203.0.113.9", "medium") is None
