"""Central, portable path resolution for CanaryGuard.

Everything the stack writes (state files, secrets, feeds, the database when
configured relative) is anchored to a single home directory instead of
hard-coded per-machine paths:

    CANARYGUARD_HOME  ->  used verbatim when set
    otherwise         ->  the repository root (parent of this package)

This keeps the repo portable across machines, OSes and CI runners.
"""

import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def home() -> str:
    return os.environ.get("CANARYGUARD_HOME") or BASE_DIR


def state_file(name: str) -> str:
    """Path to a runtime state file inside the CanaryGuard home directory."""
    return os.path.join(home(), name)


def ensure_home() -> str:
    path = home()
    os.makedirs(path, exist_ok=True)
    return path
