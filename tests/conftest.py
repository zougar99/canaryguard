import os
import sys
import tempfile

# isolate machine-local state (secret.key, feeds/, state files) before any imports
os.environ.setdefault("CANARYGUARD_HOME", tempfile.mkdtemp(prefix="canaryguard-test-"))
os.environ.pop("CANARYGUARD_SECRET_KEY", None)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
