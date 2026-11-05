"""At-rest encryption for sensitive columns (Fernet / AES-128-CBC + HMAC).

Captured credentials, keystrokes and secret-scanner hits are the crown jewels
of a honeypot host. This module encrypts them before they reach SQLite and
decrypts transparently on read.

Key resolution order:
    1. CANARYGUARD_SECRET_KEY env var (urlsafe-base64, 32 bytes)
    2. <home>/secret.key  (created automatically with 0600 perms)

If the `cryptography` package is unavailable the module degrades to a
pass-through and logs a loud warning — data stays readable, nothing crashes,
but nothing is encrypted either.
"""

import base64
import os
import secrets
import sys

from .paths import home

PREFIX = "enc:v1:"

try:
    from cryptography.fernet import Fernet

    _HAVE_CRYPTO = True
except Exception:  # pragma: no cover - dependency missing
    Fernet = None
    _HAVE_CRYPTO = False
    print("[cryptostore] WARNING: 'cryptography' package not installed — "
          "sensitive DB columns will be stored UNENCRYPTED. "
          "pip install cryptography", file=sys.stderr)

_fernet = None
_warned = False


def _key_path() -> str:
    return os.path.join(home(), "secret.key")


def _load_key() -> bytes:
    env_key = os.environ.get("CANARYGUARD_SECRET_KEY", "").strip()
    if env_key:
        raw = env_key.encode("ascii")
        try:
            # validate shape early with a clear error
            Fernet(raw)
            return raw
        except Exception as exc:
            raise RuntimeError(f"CANARYGUARD_SECRET_KEY is not a valid Fernet key: {exc}") from exc
    path = _key_path()
    if os.path.exists(path):
        with open(path, "rb") as fh:
            return fh.read().strip()
    key = Fernet.generate_key()
    try:
        with open(path, "wb") as fh:
            fh.write(key)
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass  # best effort on Windows
    except Exception:
        # fall back to an in-memory key: sessions still work, restart loses access
        print("[cryptostore] WARNING: could not persist secret.key — "
              "encrypted data will be unreadable after restart", file=sys.stderr)
    return key


def _get_fernet():
    global _fernet
    if _fernet is None:
        if not _HAVE_CRYPTO:
            return None
        _fernet = Fernet(_load_key())
    return _fernet


def encrypt(value):
    """Encrypt a string for storage. Non-strings pass through untouched."""
    if value is None:
        return None
    if not isinstance(value, str):
        value = str(value)
    if value.startswith(PREFIX):
        return value  # already encrypted
    f = _get_fernet()
    if f is None:
        return value  # pass-through mode
    return PREFIX + f.encrypt(value.encode("utf-8")).decode("ascii")


def decrypt(value):
    """Decrypt a stored value. Plaintext legacy values are returned as-is."""
    if not isinstance(value, str) or not value.startswith(PREFIX):
        return value
    f = _get_fernet()
    if f is None:
        return value  # cannot decrypt without the library — return as stored
    try:
        return f.decrypt(value[len(PREFIX):].encode("ascii")).decode("utf-8")
    except Exception:
        return "<undecryptable>"


def is_encrypted(value) -> bool:
    return isinstance(value, str) and value.startswith(PREFIX)


def generate_key() -> str:
    """Return a fresh base64 key suitable for CANARYGUARD_SECRET_KEY."""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")
