"""Reachability hints on Pkarr (DHT Reachability Hints Profile §9, v0.9; spec-gap 105) — reference for `pkarr/` vectors.

Spec: §8.1, §8.3, §8.5; DHT Hints Profile §9. A `did:key` identity publishes `_dsip` TXT records in its own Pkarr zone
(a BEP 44 mutable item signed by the identity key, seq = the timestamp). A reader verifies the payload offline and
turns it into a hint of the hints tier — never authority.

Impl (spec-gap 105): DSIP adds the checks Pkarr omits — a timestamp no later than now + 300 s, canonical z-base-32,
only `_dsip.<z32>` names used (others ignored), a signed expiry of the timestamp plus the smallest TTL (≤ 3600 s) —
and resolves conflicts by §8.3, not Pkarr's "larger packet wins".
"""
from __future__ import annotations

import struct

from .crypto import b58_decode, b58_encode, ed25519_verify

ZB32 = "ybndrfg8ejkmcpqxot1uwisza345h769"
FUTURE_TOLERANCE_S = 300
MAX_TTL = 3600
TXT, IN = 16, 1


class Reject(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def z32_encode(b: bytes) -> str:
    n, bits = int.from_bytes(b, "big"), len(b) * 8
    pad = (-bits) % 5
    n <<= pad
    return "".join(ZB32[(n >> (bits + pad - 5 * (i + 1))) & 31] for i in range((bits + pad) // 5))


def z32_decode(s: str) -> bytes:
    """52 characters → 32 bytes; the 4 padding bits must be zero (canonical)."""
    if len(s) != 52 or any(c not in ZB32 for c in s):
        raise Reject("malformed")
    n = 0
    for c in s:
        n = (n << 5) | ZB32.index(c)
    if n & 0xF:
        raise Reject("non-canonical")
    return (n >> 4).to_bytes(32, "big")


def bep44_signable(seq: int, value: bytes, salt: bytes = b"") -> bytes:
    """BEP 44's signed buffer: [4:salt<len>:<salt>]3:seqi<seq>e1:v<len>:<value> (value a byte string)."""
    pre = b"4:salt%d:" % len(salt) + salt if salt else b""
    return pre + b"3:seqi%de1:v%d:" % (seq, len(value)) + value


def did_key_public(did: str) -> bytes:
    if not isinstance(did, str) or not did.startswith("did:key:z"):
        raise Reject("not-did-key")
    try:
        raw = b58_decode(did[len("did:key:z"):])
    except Exception:
        raise Reject("not-did-key")
    if len(raw) != 34 or raw[:2] != b"\xed\x01":
        raise Reject("not-did-key")
    return raw[2:]


def did_key(pub: bytes) -> str:
    return "did:key:z" + b58_encode(b"\xed\x01" + pub)


# --- DNS (RFC 1035) ----------------------------------------------------------------------------

def _name(pkt: bytes, off: int) -> tuple[tuple, int]:
    """A domain name at `off` (compression pointers must point backwards); → (lowercased labels, next offset)."""
    labels, end, start = [], None, off
    while True:
        if off >= len(pkt):
            raise Reject("malformed")
        n = pkt[off]
        if n & 0xC0 == 0xC0:
            if off + 1 >= len(pkt):
                raise Reject("malformed")
            ptr = ((n & 0x3F) << 8) | pkt[off + 1]
            if ptr >= start:
                raise Reject("malformed")
            if end is None:
                end = off + 2
            off = start = ptr
            continue
        if n & 0xC0:
            raise Reject("malformed")
        if n == 0:
            return tuple(lb.lower() for lb in labels), (end if end is not None else off + 1)
        if off + 1 + n > len(pkt):
            raise Reject("malformed")
        labels.append(pkt[off + 1:off + 1 + n])
        off += 1 + n


def parse_dns(pkt: bytes) -> list[tuple]:
    """The answer records `(name, type, class, ttl, rdata)`; the packet must parse exactly to its end."""
    if len(pkt) < 12:
        raise Reject("malformed")
    _id, _flags, qd, an, ns, ar = struct.unpack("!HHHHHH", pkt[:12])
    off, answers = 12, []
    for _ in range(qd):
        _, off = _name(pkt, off)
        off += 4
    for i in range(an + ns + ar):
        name, off = _name(pkt, off)
        if off + 10 > len(pkt):
            raise Reject("malformed")
        rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", pkt[off:off + 10])
        off += 10
        if off + rdlen > len(pkt):
            raise Reject("malformed")
        if i < an:
            answers.append((name, rtype, rclass, ttl, pkt[off:off + rdlen]))
        off += rdlen
    if off != len(pkt):
        raise Reject("malformed")
    return answers


def txt_strings(rdata: bytes) -> list[bytes]:
    out, i = [], 0
    while i < len(rdata):
        n = rdata[i]
        if i + 1 + n > len(rdata):
            raise Reject("malformed")
        out.append(rdata[i + 1:i + 1 + n])
        i += 1 + n
    return out


def endpoint(strings: list[bytes]) -> dict:
    """`uri=` (exactly one, wss://), `b=` (one or more), `svc=` (at most one); unknown keys ignored."""
    uris, bindings, svcs = [], [], []
    for s in strings:
        try:
            t = s.decode("utf-8")
        except UnicodeDecodeError:
            raise Reject("bad-endpoint")
        if "=" not in t:
            raise Reject("bad-endpoint")
        k, v = t.split("=", 1)
        {"uri": uris, "b": bindings, "svc": svcs}.get(k, []).append(v)
    if len(uris) != 1 or not uris[0].startswith("wss://") or not bindings or len(svcs) > 1:
        raise Reject("bad-endpoint")
    ep = {"uri": uris[0], "bindings": bindings}
    if svcs:
        ep["service"] = svcs[0]
    return ep


# --- reading a hint ----------------------------------------------------------------------------

def read(did: str, payload: bytes, now: int) -> dict:
    """A relay payload (signature ‖ timestamp ‖ DNS packet) for `did` → the hint, or Reject."""
    pub = did_key_public(did)
    if payload is None or not 72 <= len(payload) <= 1072:
        raise Reject("malformed")
    sig, ts, dns = payload[:64], struct.unpack("!Q", payload[64:72])[0], payload[72:]
    if not ed25519_verify(pub, bep44_signable(ts, dns), sig):
        raise Reject("signature")
    if ts > 2**53 - 1:  # Impl: exact as a JSON number (BEP 44 allows 2^63−1)
        raise Reject("malformed")
    if ts > (now + FUTURE_TOLERANCE_S) * 1_000_000:
        raise Reject("future")
    owner = (b"_dsip", z32_encode(pub).encode())
    eps, ttls = [], []
    for name, rtype, rclass, ttl, rdata in parse_dns(dns):
        if name != owner or rtype != TXT or rclass != IN:
            continue  # another record of this key's zone (or outside it): not DSIP's
        eps.append(endpoint(txt_strings(rdata)))
        ttls.append(ttl)
    if not eps:
        raise Reject("no-endpoints")
    if max(ttls) > MAX_TTL:
        raise Reject("ttl-too-long")
    issued = ts // 1_000_000
    expires = issued + min(ttls)
    if now >= expires:
        raise Reject("expired")
    return {"subject": did, "seq": ts, "issued_at": issued, "expires_at": expires, "endpoints": eps}


def unhex(s) -> bytes | None:
    try:
        return bytes.fromhex(s) if isinstance(s, str) and len(s) % 2 == 0 else None
    except ValueError:
        return None


def run(v: dict):
    i = v["input"]
    c = i["check"]
    h = bytes.fromhex
    try:
        if c == "hint":
            return {"outcome": "hint", **read(i["did"], unhex(i["payload"]), i["now"])}
        if c == "select":
            new = read(i["did"], unhex(i["payload"]), i["now"])
            try:
                held = read(i["did"], unhex(i["held"]), i["now"])
            except Reject:
                return {"winner": "input", "conflict": "none"}
            if new["seq"] > held["seq"]:
                return {"winner": "input", "conflict": "newer-seq"}
            if new["seq"] < held["seq"]:
                return {"winner": "held", "conflict": "older-seq"}
            return {"winner": "held", "conflict": "none" if i["payload"] == i["held"] else "same-seq-live"}
        if c == "bep44-signable":
            return {"bytes": bep44_signable(i["seq"], h(i["value"]), h(i["salt"]) if i.get("salt") else b"").hex()}
        if c == "bep44-verify":
            m = bep44_signable(i["seq"], h(i["value"]), h(i["salt"]) if i.get("salt") else b"")
            return {"valid": ed25519_verify(h(i["public_key"]), m, h(i["signature"]))}
        if c == "z32-encode":
            return {"z32": z32_encode(h(i["key"]))}
        if c == "z32-decode":
            return {"key": z32_decode(i["z32"]).hex()}
    except Reject as r:
        return {"outcome": "rejected", "reason": r.reason}
    raise KeyError(c)
