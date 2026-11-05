"""Change-point detection on the event rate — A2 from the roadmap.

Catches slow-and-low attack ramps that fixed per-IP windows miss entirely.
CUSUM over robustly normalized one-minute buckets (median/MAD baseline, so
the attack ramp itself cannot inflate the baseline it is measured against),
with an EWMA mean kept for display/stats. Pure Python.

    det = RateChangeDetector()
    for each event: det.observe()
    det.check() -> None | "spike" | "drop"
"""

import statistics
import threading
import time
from collections import deque


class RateChangeDetector:
    def __init__(self, cusum_k=1.0, cusum_h=5.0, history=180, min_baseline_minutes=10):
        self.k = cusum_k                      # CUSUM allowance (normalized units)
        self.h = cusum_h                      # CUSUM decision threshold
        self.min_baseline = min_baseline_minutes
        self.ewma_mean = None                 # smoothed rate (display)
        self.cusum_pos = 0.0
        self.cusum_neg = 0.0
        self._minute = None                   # current bucket (epoch // 60)
        self._bucket = 0
        self._recent = deque(maxlen=history)  # completed minute buckets
        self._lock = threading.Lock()

    # ---- public API ----

    def observe(self, when=None):
        now = when if when is not None else time.time()
        minute = int(now // 60)
        with self._lock:
            if self._minute is None:
                self._minute = minute
            while minute > self._minute:
                self._roll_minute(self._bucket)
                self._bucket = 0
                self._minute += 1
            self._bucket += 1

    def check(self):
        with self._lock:
            return self._status_locked()

    def stats(self):
        with self._lock:
            median, sigma = self._baseline_locked()
            return {
                "ewma_mean": self.ewma_mean,
                "baseline_median": median,
                "baseline_sigma": sigma,
                "cusum_pos": round(self.cusum_pos, 3),
                "cusum_neg": round(self.cusum_neg, 3),
                "recent_minutes": list(self._recent),
                "status": self._status_locked(),
            }

    def reset(self):
        with self._lock:
            self.ewma_mean = None
            self.cusum_pos = 0.0
            self.cusum_neg = 0.0
            self._minute = None
            self._bucket = 0
            self._recent.clear()

    # ---- internals ----

    def _baseline_locked(self):
        data = list(self._recent)
        if len(data) < self.min_baseline:
            return None, None
        median = statistics.median(data)
        mad = statistics.median([abs(x - median) for x in data]) if data else 0.0
        sigma = max(1.4826 * mad, 1.0)  # floor of 1 event/min — never absurdly sensitive
        return median, sigma

    def _status_locked(self):
        median, sigma = self._baseline_locked()
        if median is None:
            return None
        if self.cusum_pos > self.h:
            return "spike"
        if self.cusum_neg > self.h:
            return "drop"
        return None

    def _roll_minute(self, count):
        median, sigma = self._baseline_locked()
        if median is not None:
            # normalized deviation against the *pre-existing* baseline
            dev = (count - median) / sigma
            self.cusum_pos = max(0.0, self.cusum_pos + dev - self.k)
            self.cusum_neg = max(0.0, self.cusum_neg - dev - self.k)
        # EWMA for display only
        if self.ewma_mean is None:
            self.ewma_mean = float(count)
        else:
            self.ewma_mean += 0.3 * (count - self.ewma_mean)
        self._recent.append(count)
