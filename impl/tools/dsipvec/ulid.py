"""ULID encode/decode with timestamp extraction (spec §10.3, §12.6, §20.6)."""
from __future__ import annotations

import hashlib
import re

CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
ULID_RE = re.compile(r"^[0-7][0-9A-HJKMNP-TV-Z]{25}$")
_DECODE = {c: i for i, c in enumerate(CROCKFORD)}


def encode(ts_ms: int, rand: bytes) -> str:
    if len(rand) != 10:
        raise ValueError("ULID randomness must be 10 bytes")
    if not (0 <= ts_ms < (1 << 48)):
        raise ValueError("ULID timestamp out of range")
    n = (ts_ms << 80) | int.from_bytes(rand, "big")
    out = []
    for _ in range(26):
        out.append(CROCKFORD[n & 31])
        n >>= 5
    return "".join(reversed(out))


def is_valid(s: str) -> bool:
    return isinstance(s, str) and ULID_RE.match(s) is not None


def timestamp_ms(s: str) -> int:
    """Timestamp component in milliseconds. Caller must have validated shape."""
    n = 0
    for ch in s[:10]:
        n = (n << 5) | _DECODE[ch]
    return n


def deterministic(ts_ms: int, label: str) -> str:
    """ULID with timestamp `ts_ms` and randomness derived from `label` (vector reproducibility)."""
    rand = hashlib.sha256(f"dsip-ulid:{label}".encode()).digest()[:10]
    return encode(ts_ms, rand)
