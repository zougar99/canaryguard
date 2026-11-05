"""Shell-command triage — A8 from the roadmap.

Character-level heuristics that tell scripted spray (low-entropy, high
metacharacter density) from an interactive human (mixed tokens, dictionary
words, natural pacing). Not a trained model — an explainable heuristic
scorer with a clear report.
"""

import math
import re
from collections import Counter

_METACHARS = set(";|&`$<>{}[]()\\/%*?!\n")
_URL_RE = re.compile(r"https?://|\.sh|\.ps1|powershell|cmd\.exe|encodedcommand|-enc\b", re.I)
_B64_BLOB_RE = re.compile(r"[A-Za-z0-9+/=]{40,}")


def shannon_entropy_bits(text):
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def tokenize(text):
    return re.findall(r"\S+", text or "")


def metachar_ratio(text):
    if not text:
        return 0.0
    return sum(1 for c in text if c in _METACHARS) / len(text)


def classify(command):
    """Return {'label': 'scripted'|'human', 'score': 0..1, 'features': {...}}."""
    cmd = command or ""
    tokens = tokenize(cmd)
    features = {
        "length": len(cmd),
        "tokens": len(tokens),
        "entropy_bits": round(shannon_entropy_bits(cmd), 3),
        "metachar_ratio": round(metachar_ratio(cmd), 3),
        "has_url_or_exec": bool(_URL_RE.search(cmd)),
        "avg_token_len": round(sum(len(t) for t in tokens) / len(tokens), 2) if tokens else 0.0,
    }
    features["has_b64_blob"] = bool(_B64_BLOB_RE.search(cmd))
    score = 0.0
    if features["metachar_ratio"] > 0.20:
        score += 0.30
    if features["has_url_or_exec"]:
        score += 0.35
    if features["has_b64_blob"]:
        score += 0.30
    # very long single-train commands with high entropy are packed/encoded payloads
    if features["length"] > 80 and features["entropy_bits"] > 4.2:
        score += 0.20
    if tokens and features["avg_token_len"] > 40:
        score += 0.20
    if features["entropy_bits"] < 2.5 and len(tokens) <= 3:
        score -= 0.15  # "ls", "id" — routine human input
    label = "scripted" if score >= 0.5 else "human"
    return {"label": label, "score": round(max(0.0, min(1.0, score)), 3), "features": features}
