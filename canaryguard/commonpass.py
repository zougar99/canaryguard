"""Common/breached password recognition — A5 from the roadmap.

A local Bloom filter pre-seeded with notorious passwords; drop extra lists
(one password per line) into <home>/feeds/breached-passwords.txt to extend it.
False positives are near-zero for adversarial inputs; the filter is advisory,
never a verdict on its own.
"""

import hashlib
import math
import os

from .paths import home

# Seed: the usual suspects (rockyou top entries, keyboard walks, defaults).
TOP_PASSWORDS = """
123456 123456789 qwerty 12345678 111111 1234567890 1234567 password 123123 987654321
12345 123321 qwerty123 1q2w3e password1 123456a 123123123 admin 12345678910
abc123 iloveyou 1234 1q2w3e4r qwertyuiop 000000 password123 zaq12wsx
dragon 123qwe 123456789a sunshine master 123654 654321 123qweasd qwerty1 1234567890a
monkey letmein abc123456 666666 123321a 123Abc myspace1 password12 123456q zxcvbnm
123123123a 1234qwer 1qaz2wsx superman 111111a 123321q princess dragon1 123qwe123
qwerty123a 121212 xxxxxx 1q2w3e4r5t 12344321 1qazxsw2 654321a 123abc !@#$%^&*
""".split()


class BloomFilter:
    def __init__(self, capacity=10000, error_rate=0.001):
        self.capacity = int(capacity)
        self.error_rate = float(error_rate)
        self.size = max(64, int(-self.capacity * math.log(self.error_rate) / (math.log(2) ** 2)))
        self.hashes = max(1, int(self.size / self.capacity * math.log(2)))
        self.bits = bytearray((self.size + 7) // 8)

    def _positions(self, item):
        data = item.encode("utf-8", "ignore")
        h1 = int.from_bytes(hashlib.sha256(data).digest()[:8], "big")
        h2 = int.from_bytes(hashlib.blake2b(data, digest_size=8).digest(), "big") | 1
        for i in range(self.hashes):
            yield (h1 + i * h2) % self.size

    def add(self, item):
        for pos in self._positions(item):
            self.bits[pos // 8] |= 1 << (pos % 8)

    def __contains__(self, item):
        return all(self.bits[pos // 8] & (1 << (pos % 8)) for pos in self._positions(item))

    def __len__(self):
        return sum(bin(b).count("1") for b in self.bits)  # set bits, not unique keys


def _build():
    bf = BloomFilter(capacity=max(10000, len(TOP_PASSWORDS) * 4))
    for pw in TOP_PASSWORDS:
        bf.add(pw.lower())
    # optional external list
    extra = os.path.join(home(), "feeds", "breached-passwords.txt")
    try:
        if os.path.exists(extra):
            with open(extra, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip().lower()
                    if line and not line.startswith("#"):
                        bf.add(line)
    except Exception:
        pass
    return bf


_built = None


def _filter():
    global _built
    if _built is None:
        _built = _build()
    return _built


def is_common_password(password) -> bool:
    if not password:
        return False
    return password.lower() in _filter()
