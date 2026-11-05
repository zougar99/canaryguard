from canaryguard.classifier import AttackProfiler, classify, extract_creds


def test_skip_logtypes():
    assert classify({"logtype": 1000}) == (None, None, None, None, None)


def test_ssh_brute_force_becomes_critical():
    event = {"logtype": 4002, "logdata": {"USERNAME": "root", "PASSWORD": "toor"}}
    category, service, severity, creds, _ = classify(event)
    assert category == "brute_force"
    assert service == "ssh"
    assert severity == "critical"
    assert creds == {"username": "root", "password": "toor", "service": "ssh"}


def test_http_attack_path_detected():
    event = {"logtype": 3000, "logdata": {"PATH": "/../../etc/passwd"}}
    category, service, severity, *_ = classify(event)
    assert category == "exploit_attempt"
    assert severity == "high"


def test_http_sensitive_path():
    event = {"logtype": 3000, "logdata": {"PATH": "/admin/panel"}}
    category, _, severity, *_ = classify(event)
    assert category == "sensitive_access"
    assert severity == "medium"


def test_unknown_logtype():
    event = {"logtype": 999999, "logdata": {}}
    category, service, severity, *_ = classify(event)
    assert category == "unknown"
    assert severity == "medium"


def test_extract_creds_case_insensitive_keys():
    assert extract_creds({"username": "a", "password": "b"}, "ftp")["username"] == "a"
    assert extract_creds({"USERNAME": "A", "PASSWORD": "B"}, "ftp")["username"] == "A"
    assert extract_creds("notadict", "ftp") is None


def test_profiler_escalates_burst():
    profiler = AttackProfiler()
    profile = {}
    for _ in range(6):
        profile = profiler.update("203.0.113.7", "brute_force", "root")
    assert profile["brute_attempts_5min"] >= 5
    assert profile["score"] >= 40
    assert profile["label"] in ("persistent attacker", "aggressive attacker")
