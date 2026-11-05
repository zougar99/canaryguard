"""Periodicity (beacon) detection — A7 from the roadmap.

C2-style implants call home on a schedule. A plain autocorrelation over
inter-connection intervals exposes the rhythm even when every single
connection looks innocent. Pure Python.
"""

import statistics
from datetime import datetime


def analyze_intervals(timestamps):
    """timestamps: iterable of datetime. Returns periodicity metrics."""
    times = sorted(timestamps)
    if len(times) < 6:
        return {"is_beacon": False, "reason": "not enough samples", "samples": len(times)}
    intervals = [(times[i + 1] - times[i]).total_seconds() for i in range(len(times) - 1)]
    intervals = [i for i in intervals if i > 0]
    if len(intervals) < 5:
        return {"is_beacon": False, "reason": "not enough intervals", "samples": len(times)}

    median = statistics.median(intervals)
    if median <= 0:
        return {"is_beacon": False, "reason": "zero median interval", "samples": len(times)}

    # normalize: fraction of intervals within 10% of the median
    near = sum(1 for i in intervals if abs(i - median) <= 0.10 * median) / len(intervals)
    # coefficient of variation — beacons are metronomes
    mean = statistics.fmean(intervals)
    stdev = statistics.pstdev(intervals)
    cov = stdev / mean if mean else 1.0

    # autocorrelation at the dominant lag is approximated by the near-median fraction
    score = round(near * (1.0 - min(cov, 1.0)), 3)
    is_beacon = near >= 0.6 and cov <= 0.35

    return {
        "is_beacon": is_beacon,
        "samples": len(times),
        "median_interval_s": round(median, 2),
        "mean_interval_s": round(mean, 2),
        "cov": round(cov, 3),
        "regularity": round(near, 3),
        "score": score,
    }


def find_beacons(store, hours=24, limit_remotes=200):
    """Analyse net_events for periodic remotes. Returns list of findings."""
    since = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rows = store.fetchall(
        "SELECT remote, ts FROM net_events WHERE remote IS NOT NULL AND remote != '' "
        "AND ts >= datetime('now','localtime', ?) ORDER BY remote, ts",
        (f"-{int(hours)} hours",),
    )
    by_remote = {}
    for row in rows:
        by_remote.setdefault(row["remote"], []).append(row["ts"])

    findings = []
    for remote, ts_list in list(by_remote.items())[:limit_remotes]:
        parsed = []
        for ts in ts_list:
            try:
                parsed.append(datetime.strptime(str(ts)[:19], "%Y-%m-%d %H:%M:%S"))
            except ValueError:
                continue
        result = analyze_intervals(parsed)
        if result.get("is_beacon"):
            result["remote"] = remote
            findings.append(result)
    findings.sort(key=lambda f: f.get("score", 0), reverse=True)
    return findings
