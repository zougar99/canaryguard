import time
from datetime import datetime, timedelta

from canaryguard.beacon import analyze_intervals
from canaryguard.changepoint import RateChangeDetector
from canaryguard.commonpass import is_common_password
from canaryguard.credgraph import analyze
from canaryguard.markov import classify as markov_classify
from canaryguard.rarity import RarityModel, bump_once
from canaryguard.spray import SprayDetector


class _FakeConfig:
    def __init__(self, data=None):
        self.data = data or {}

    def section(self, *keys, **kwargs):
        node = self.data
        for key in keys:
            node = node.get(key, {}) if isinstance(node, dict) else {}
        return node if isinstance(node, dict) else {}

    def get(self, *keys, default=None):
        node = self.data
        for key in keys:
            if not isinstance(node, dict) or key not in node:
                return default
            node = node[key]
        return node


# ---------- rarity ----------

def test_rarity_empty_store_is_novel(tmp_path):
    from canaryguard.logstore import LogStore

    store = LogStore(str(tmp_path / "r.db"))
    model = RarityModel(_FakeConfig(), store=store)
    rarity, count = model.score("ssh", "brute_force")
    assert rarity == 1.0
    assert count == 0
    store.close()


def test_rarity_frequent_pair_scores_low(tmp_path):
    from canaryguard.logstore import LogStore

    store = LogStore(str(tmp_path / "r2.db"))
    for i in range(30):
        store.insert_event("2026-11-05 10:00:00", 4002, f"203.0.113.{i}", 1, 22,
                           "brute_force", "high", {"service": "ssh"})
    model = RarityModel(_FakeConfig(), store=store)
    model._cache_total = (0.0, 30)  # deterministic baseline
    store._cache = {} if False else model._cache
    model._cache[("ssh", "brute_force")] = (time.monotonic(), 30)
    rarity, count = model.score("ssh", "brute_force")
    assert count == 30
    assert rarity < 0.9
    assert RarityModel.should_boost(0.95, 0)
    assert not RarityModel.should_boost(0.5, 0)
    store.close()


def test_bump_once():
    assert bump_once("medium") == "high"
    assert bump_once("critical") == "critical"
    assert bump_once("weird") == "weird"


# ---------- changepoint ----------

def test_changepoint_detects_ramp():
    det = RateChangeDetector(cusum_k=1.0, cusum_h=5.0, min_baseline_minutes=10)
    base = time.time() - 40 * 60
    for minute in range(30):          # 30 minutes of quiet baseline (~10 events)
        for _ in range(10):
            det.observe(when=base + minute * 60 + 1)
    assert det.check() is None
    for _ in range(60):               # one loud minute arrives
        det.observe(when=base + 30 * 60 + 1)
    for _ in range(60):
        det.observe(when=base + 31 * 60 + 1)
    assert det.check() == "spike"


# ---------- spray ----------

def test_password_spray_across_ips():
    det = SprayDetector(window_seconds=600, min_ips_same_password=3, min_users_same_ip=99)
    finding = None
    for i in range(3):
        out = det.observe(f"203.0.113.{i}", "admin", "Summer2026!", "ssh", when=time.monotonic())
        if out:
            finding = out[0]
    assert finding is not None
    assert finding["kind"] == "password_spray"
    assert finding["distinct_ips"] == 3


def test_username_fanout_from_one_ip():
    det = SprayDetector(window_seconds=600, min_ips_same_password=99, min_users_same_ip=5)
    finding = None
    for i in range(5):
        out = det.observe("203.0.113.99", f"user{i}", f"pw{i}", "ssh", when=time.monotonic())
        if out:
            finding = out[0]
    assert finding is not None
    assert finding["kind"] == "user_fanout"
    assert finding["distinct_usernames"] == 5


def test_spray_cooldown_suppresses_duplicates():
    det = SprayDetector(window_seconds=600, min_ips_same_password=2, min_users_same_ip=99)
    t = time.monotonic()
    det.observe("203.0.113.1", "a", "samePw!", "ssh", when=t)
    first = det.observe("203.0.113.2", "b", "samePw!", "ssh", when=t)
    second = det.observe("203.0.113.3", "c", "samePw!", "ssh", when=t)
    assert first and first[0]["kind"] == "password_spray"
    assert second is None  # cooldown swallowed the repeat


# ---------- commonpass ----------

def test_common_passwords():
    assert is_common_password("123456")
    assert is_common_password("Password".lower())
    assert not is_common_password("Qwz!x8v-Lm2$Kp9Tz#wQ7")


# ---------- credgraph ----------

def test_credgraph_finds_stuffing_cluster():
    rows = [{"src_ip": f"203.0.113.{i}", "username": "alice", "password": "sharedPw1"}
            for i in range(4)]
    result = analyze(rows, min_ips=3)
    assert result["clusters"], "expected one cluster"
    top = result["clusters"][0]
    assert top["distinct_ips"] == 4
    # masked password only — never raw
    assert all("sharedPw1" != p for p in top["passwords"])


def test_credgraph_ignores_small_groups():
    rows = [{"src_ip": f"203.0.113.{i}", "username": "alice", "password": f"pw-{i}"}
            for i in range(2)]
    assert analyze(rows, min_ips=3)["clusters"] == []


# ---------- beacon ----------

def test_beacon_detects_metronome():
    t0 = datetime(2026, 11, 5, 0, 0, 0)
    times = [t0 + timedelta(seconds=60 * i) for i in range(24)]
    report = analyze_intervals(times)
    assert report["is_beacon"]
    assert report["median_interval_s"] == 60


def test_beacon_ignores_irregular():
    t0 = datetime(2026, 11, 5, 0, 0, 0)
    times = [t0 + timedelta(seconds=s) for s in (0, 3, 41, 999, 1200, 1230, 4200)]
    report = analyze_intervals(times)
    assert not report["is_beacon"]


# ---------- markov ----------

def test_markov_scripted_vs_human():
    scripted = markov_classify("powershell -nop -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ADsAOw==")
    assert scripted["label"] == "scripted"
    human = markov_classify("ls")
    assert human["label"] == "human"
