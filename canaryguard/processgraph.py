"""Process parent→child rarity — B1 from the roadmap.

Attackers spawn processes from unusual parents (winword -> powershell,
explorer -> rundll32 with odd args). Count every observed pair forever;
pairs never seen before (after a warm-up) are flagged. Pure counting,
no model to train.
"""

from .config import get_store


class ProcessPairModel:
    def __init__(self, config=None, store=None, warmup=200):
        self.store = store or get_store(config)
        self.warmup = int(warmup)

    def observe(self, parent, child):
        parent = (parent or "").lower().strip()
        child = (child or "").lower().strip()
        if not parent or not child:
            return None
        pair = f"{parent} -> {child}"
        count, total = self.store.observe_proc_pair(pair)
        return {
            "pair": pair,
            "count": count,
            "total_observations": total,
            "is_rare": total >= self.warmup and count == 1,
        }
