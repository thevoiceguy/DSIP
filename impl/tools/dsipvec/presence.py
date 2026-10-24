"""Presence Profile (`presence/0.1`, `presence/0.2`, v0.17 draft) — the subscriber's combining rule, sealed records
and the profile's timers.

Spec: P§4 (several devices' records combined into one identity's presence), P§5 (the open state registry and its
fallback), P§8 (timers), P§12 (sealed records: keys, sealing, keys in a grant, what a subscriber can read). The
authority's side of P§3 is `broadcast.Authority`.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re

from .registry import PRESENCE_STATES, PRESENCE_STATE_FALLBACK

RECORD_MIN_LIFETIME_S = 60      # P§8
RECORD_MAX_LIFETIME_S = 3600    # P§8, §12.9
PRESENCE_GRACE_S = 60           # P§8 T-Presence-Grace default (bounds 0–300)
PUBLISH_INTERVAL_S = 5          # P§8: between two accepted records of one device

# P§4 starting order, highest first
RANK = {"dnd": 4, "busy": 3, "available": 2, "away": 1, "offline": 0}


def effective_state(token: str) -> str:
    """P§5: a registered state stands; an unknown one is shown as available."""
    return token if token in PRESENCE_STATES else PRESENCE_STATE_FALLBACK


def aggregate(records: list[dict], asserted: str | None, now: int) -> dict:
    """P§4: the identity's presence from the records a subscriber holds (each `{state, expires_at, device?}`) and the
    body's assertion. Returns `{state, token, source}`: the effective state, the token that won, and `record`,
    `assertion` or `none`."""
    # (rank, record before assertion, registered first, token in code-point order)
    candidates = [(r["state"], "record") for r in records if r["expires_at"] > now]
    if asserted == "available":
        candidates.append(("available", "assertion"))
    if not candidates:
        return {"state": "offline", "token": "offline", "source": "none"}

    def key(c):
        token, source = c
        return (-RANK[effective_state(token)], source != "record", token not in PRESENCE_STATES, token)

    token, source = min(candidates, key=key)
    return {"state": effective_state(token), "token": token, "source": source}


# ---------------------------------------------------------------- sealed records (P§12)

PROFILE_SEALED = "presence/0.2"
PLAINTEXT_LEN = 128           # P§12.2: every sealed state is this long before encryption
NONCE_LEN, TAG_LEN = 12, 16   # AES-256-GCM as M§11.1
SEALED_LEN = NONCE_LEN + PLAINTEXT_LEN + TAG_LEN
KEYS_ALG = "hpke-base-x25519-sha256-aes128gcm"  # P§12.3, the sealed purpose's suite (§19.4)
KEYS_INFO = b"dsip presence keys v1"
TOKEN = re.compile(r"[a-z][a-z0-9-]*")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def clamp(sk: bytes) -> bytes:
    """RFC 7748 decodeScalar25519: P§12.1 derives from the key agreement secret as clamped."""
    b = bytearray(sk)
    b[0] &= 248
    b[31] &= 127
    b[31] |= 64
    return bytes(b)


def hkdf(ikm: bytes, info: bytes, n: int) -> bytes:
    """RFC 5869 HKDF-SHA256 with an empty salt (P§12.1)."""
    prk = hmac.new(b"\0" * 32, ikm, hashlib.sha256).digest()
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:n]


def audience_tag(secret: bytes, subject: str, label: str) -> str:
    """P§12.1: the wire name of an audience the subject labels `label`."""
    raw = hkdf(clamp(secret), b"dsip presence audience v1\0" + subject.encode() + b"\0" + label.encode(), 10)
    return "k-" + base64.b32encode(raw).decode().lower().rstrip("=")


def presence_key(secret: bytes, subject: str, kid: str) -> bytes:
    """P§12.1: the 32-byte key a `kid` names."""
    return hkdf(clamp(secret), b"dsip presence key v1\0" + subject.encode() + b"\0" + kid.encode(), 32)


def record_aad(r: dict) -> bytes:
    """P§12.2: binds the ciphertext to its subject, device, audience, key, seq and expiry."""
    parts = [b"dsip presence v1", r["subject"].encode(), r["device"].encode(), r.get("audience", "").encode(),
             r["kid"].encode()]
    return b"\0".join(parts) + b"\0" + r["seq"].to_bytes(8, "big") + r["expires_at"].to_bytes(8, "big")


def kid_scope(kid: str) -> str:
    return kid.rsplit(".", 1)[0]


def seal_record(r: dict, state: str, key: bytes, nonce: bytes) -> str:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    pt = json.dumps({"state": state}, separators=(",", ":")).encode().ljust(PLAINTEXT_LEN, b" ")
    return _b64e(nonce + AESGCM(key).encrypt(nonce, pt, record_aad(r)))


def open_record(r: dict, keys: dict[str, bytes]) -> dict:
    """P§12.4: a sealed record's state, or why it is unreadable, in the profile's order."""
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = keys.get(r["kid"])
    if key is None:
        return {"verdict": "reject", "code": "presence-key-unknown"}
    try:
        sealed = _b64d(r["sealed_state"])
    except ValueError:
        sealed = b""
    if len(sealed) != SEALED_LEN:
        return {"verdict": "reject", "code": "sealed-too-short"}
    try:
        pt = AESGCM(key).decrypt(sealed[:NONCE_LEN], sealed[NONCE_LEN:], record_aad(r))
    except InvalidTag:
        return {"verdict": "reject", "code": "aead-open-failed"}
    try:
        body = json.loads(pt.decode("utf-8"))
    except ValueError:
        body = None
    if (len(pt) != PLAINTEXT_LEN or not isinstance(body, dict) or set(body) != {"state"}
            or not isinstance(body["state"], str) or len(body["state"]) > 64 or not TOKEN.fullmatch(body["state"])):
        return {"verdict": "reject", "code": "presence-plaintext-invalid"}
    return {"verdict": "accept", "state": body["state"]}


def open_grant_keys(g: dict, recipient_secret: bytes) -> dict:
    """P§12.3: the keys a grant's `presence_keys` carries, as `{kid: key_hex}`, or why they cannot be read."""
    from .messaging import hpke_open
    pk = g["presence_keys"]
    if pk["alg"] != KEYS_ALG:
        return {"verdict": "reject", "code": "sealed-alg-unsupported"}
    aad = g["id"].encode() + b"\0" + g["from"].encode() + b"\0" + g["to"].encode()
    try:
        enc, ct = _b64d(pk["enc"]), _b64d(pk["ct"])
    except ValueError:
        return {"verdict": "reject", "code": "sealed-open-failed"}
    pt = hpke_open(enc, clamp(recipient_secret), KEYS_INFO, aad, ct)
    if pt is None:
        return {"verdict": "reject", "code": "sealed-open-failed"}
    bad = {"verdict": "reject", "code": "sealed-plaintext-invalid"}
    try:
        body = json.loads(pt.decode("utf-8"))
    except ValueError:
        return bad
    if len(pt) == 0 or len(pt) % 256 or not isinstance(body, dict) or set(body) != {"keys"} or not isinstance(body["keys"], list):
        return bad
    scopes = {"main"} | ({g["presence_audience"]} if "presence_audience" in g else set())
    out: dict[str, str] = {}
    for k in body["keys"]:
        if not isinstance(k, dict) or set(k) != {"kid", "key"} or not all(isinstance(k[f], str) for f in ("kid", "key")):
            return bad
        if not re.fullmatch(r"(main|[a-z][a-z0-9-]*)\.(0|[1-9][0-9]*)", k["kid"]) or kid_scope(k["kid"]) not in scopes:
            return bad
        try:
            key = _b64d(k["key"])
        except ValueError:
            return bad
        if len(key) != 32:
            return bad
        out[k["kid"]] = key.hex()
    return {"verdict": "accept", "keys": out}


def view(records: list[dict], keys: dict[str, bytes], asserted: str | None, now: int) -> dict:
    """P§12.4, P§4: the identity's presence from a body's records, sealed ones opened with the keys held; a record that
    cannot be read takes no part, and its device is listed in `unreadable`."""
    plain, unreadable = [], set()
    for r in records:
        if "sealed_state" in r:
            o = open_record(r, keys)
            if o["verdict"] != "accept":
                unreadable.add(r["device"])
                continue
            plain.append({"state": o["state"], "expires_at": r["expires_at"]})
        else:
            plain.append({"state": r["state"], "expires_at": r["expires_at"]})
    return {**aggregate(plain, asserted, now), "unreadable": sorted(unreadable)}


def run(v: dict) -> dict:
    """The `presence` vector kind: `input.check` `aggregate` (P§4), `audience-tag`, `key`, `seal-record`,
    `open-record`, `grant-keys-open` and `view` (P§12)."""
    i = v["input"]
    keys = lambda: {k: bytes.fromhex(h) for k, h in i.get("keys", {}).items()}
    c = i["check"]
    if c == "aggregate":
        return aggregate(i["records"], i.get("asserted"), v["context"]["now"])
    if c == "audience-tag":
        return {"tag": audience_tag(bytes.fromhex(i["secret_hex"]), i["subject"], i["label"])}
    if c == "key":
        return {"key_hex": presence_key(bytes.fromhex(i["secret_hex"]), i["subject"], i["kid"]).hex()}
    if c == "seal-record":
        return {"sealed_state": seal_record(i["record"], i["state"], bytes.fromhex(i["key_hex"]), bytes.fromhex(i["nonce_hex"]))}
    if c == "open-record":
        return open_record(i["record"], keys())
    if c == "grant-keys-open":
        return open_grant_keys(i["grant"], bytes.fromhex(i["recipient_secret_hex"]))
    if c == "view":
        return view(i["records"], keys(), i.get("asserted"), v["context"]["now"])
    raise ValueError(f"unknown presence check {c}")
