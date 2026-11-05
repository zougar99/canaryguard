"""Credential-spray / stuffing detector across IPs — A12 from the roadmap.

One IP hammering many usernames (spray) and one password tried from many
IPs (stuffing) are invisible to per-IP threshold logic. This keeps a
sliding window of credential attempts and reports both patterns.
"""

import threading
import time
from collections import Counter, defaultdict, deque


class SprayDetector:
    def __init__(self, window_seconds=600, min_ips_same_password=5,
                 min_users_same_ip=10, cooldown_seconds=300):
        self.window = window_seconds
        self.min_ips = min_ips_same_password
        self.min_users = min_users_same_ip
        self.cooldown = cooldown_seconds
        self._events = deque()          # (ts, ip, username, password, service)
        self._alerted = {}              # key -> monotonic ts of last alert
        self._lock = threading.Lock()

    def _prune(self, now):
        cutoff = now - self.window
        while self._events and self._events[0][0] < cutoff:
            self._events.popleft()

    def _cooled_down(self, key, now):
        last = self._alerted.get(key)
        # missing key = never alerted = ready to fire; a zero timestamp is
        # not a valid monotonic baseline on a freshly booted host
        return last is None or (now - last) >= self.cooldown

    def observe(self, src_ip, username, password, service=None, when=None):
        """Feed one credential attempt.

        Returns a finding dict when a pattern trips, else None:
            {"kind": "password_spray"|"user_fanout", ...}
        """
        if not src_ip or not password:
            return None
        now = when if when is not None else time.monotonic()
        with self._lock:
            self._prune(now)
            self._events.append((now, src_ip, username or "", password or "", service or ""))

            findings = []

            # same password from many distinct IPs
            ip_by_pw = defaultdict(set)
            for _, ip, _, pw, _ in self._events:
                if pw:
                    ip_by_pw[pw].add(ip)
            ips = ip_by_pw.get(password, set())
            if len(ips) >= self.min_ips and self._cooled_down(f"pw:{password}", now):
                self._alerted[f"pw:{password}"] = now
                findings.append({
                    "kind": "password_spray",
                    "password": password,
                    "distinct_ips": len(ips),
                    "ips": sorted(ips)[:10],
                })

            # one IP cycling through many distinct usernames
            users_by_ip = defaultdict(set)
            for _, ip, user, _, _ in self._events:
                if user:
                    users_by_ip[ip].add(user)
            users = users_by_ip.get(src_ip, set())
            if len(users) >= self.min_users and self._cooled_down(f"fanout:{src_ip}", now):
                self._alerted[f"fanout:{src_ip}"] = now
                findings.append({
                    "kind": "user_fanout",
                    "ip": src_ip,
                    "distinct_usernames": len(users),
                })

            return findings or None

    def snapshot(self):
        with self._lock:
            now = time.monotonic()
            self._prune(now)
            pw_counts = Counter(ev[3] for ev in self._events if ev[3])
            return {"window_seconds": self.window,
                    "tracked_attempts": len(self._events),
                    "top_passwords": [(mask_password(p), c) for p, c in pw_counts.most_common(5)]}


def mask_password(pw):
    if not pw:
        return ""
    if len(pw) <= 2:
        return "*" * len(pw)
    return pw[0] + "*" * (len(pw) - 2) + pw[-1]
