"""Rarity ("surprisingness") scoring — A3 from the roadmap.

Scores how unusual a (service, category) pair is against the database's own
history. Rare pairs get a severity bump at ingest time. Cheap, explainable,
no ML stack: score = 1 - log(count + 1) / log(total + 1).
"""

import time

from .config import get_store

_CACHE_TTL = 60.0  # seconds; totals/counts move slowly


class RarityModel:
    def __init__(self, config=None, store=None, logger=None):
        if store is None and config is not None:
            try:
                store = get_store(config)
            except Exception:
                store = None
        self.store = store
        self.logger = logger or print
        self._cache = {}
        self._cache_total = (0.0, 0)

    def _total(self):
        now = time.monotonic()
        ts, total = self._cache_total
        if now - ts < _CACHE_TTL:
            return total
        row = self.store.fetchall("SELECT COUNT(*) AS n FROM events")
        total = int(row[0]["n"]) if row else 0
        self._cache_total = (now, total)
        return total

    def _count(self, service, category):
        key = (service, category)
        now = time.monotonic()
        cached = self._cache.get(key)
        if cached and now - cached[0] < _CACHE_TTL:
            return cached[1]
        row = self.store.fetchall(
            "SELECT COUNT(*) AS n FROM events WHERE category=? "
            "AND raw_json LIKE ?",
            (category, f'%"{service}"%'),
        )
        count = int(row[0]["n"]) if row else 0
        self._cache[key] = (now, count)
        return count

    def score(self, service, category):
        """Return (rarity 0..1, observed_count). Higher = stranger."""
        import math

        if self.store is None:
            return 1.0, 0
        total = self._total()
        count = self._count(service, category)
        if total <= 0:
            return 1.0, 0  # no baseline yet — everything is novel
        rarity = 1.0 - math.log(count + 1) / math.log(total + 1)
        return max(0.0, min(1.0, rarity)), count

    @staticmethod
    def should_boost(rarity, count, min_total_rarity=0.80, max_count=2):
        """Boost severity for genuinely rare, barely-seen pairs."""
        return count <= max_count and rarity >= min_total_rarity


_SEV_ORDER = ["info", "low", "medium", "high", "critical"]


def bump_once(severity):
    try:
        i = _SEV_ORDER.index(severity)
    except ValueError:
        return severity
    return _SEV_ORDER[min(i + 1, len(_SEV_ORDER) - 1)]
