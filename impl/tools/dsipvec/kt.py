"""Alias Transparency Profile (draft `alias-transparency/0.1`) — reference for the `alias-transparency/` vectors.

Spec: T§2 (KEYTRANS suite 0x0002, mode 1), T§3 (alias normalization), T§5 (the building blocks: VrfInput, the VRF
index, commitments, prefix and log tree hashing, Configuration, TreeHead, the implicit search tree and binary
ladder), all per draft-ietf-keytrans-protocol (identical in -05 and the editors' copy of 2026-09-16).

Impl (spec-gap 104): ASCII-only alias normalization; VRF verification with validate_key; only suite 0x0002 and mode 1
are accepted.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import struct

from . import kt_vrf as vrf
from .crypto import ed25519_verify

KC = bytes.fromhex("d821f8790d97709796b4d7903357c3f5")  # [KT] §17.1, the 16 raw bytes
NC = 16
SUITE, MODE = 0x0002, 1
ZERO = b"\x00" * 32


def sha(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def u8(n):
    return struct.pack(">B", n)


def u16(n):
    return struct.pack(">H", n)


def u32(n):
    return struct.pack(">I", n)


def u64(n):
    return struct.pack(">Q", n)


# --- T§3 --------------------------------------------------------------------------------------

def normalize_alias(a: str) -> str | None:
    """`local@domain` → its normal form, or a `tel:` global number (README `alias`), or None (not an alias)."""
    if not isinstance(a, str):
        return None
    if a[:4].lower() == "tel:":
        rest = a[4:]
        if not rest.startswith("+"):
            return None
        digits = "".join(c for c in rest[1:] if c not in "-.()")
        return f"tel:+{digits}" if re.fullmatch(r"[1-9][0-9]{1,14}", digits) and all(c in "0123456789-.()" for c in rest[1:]) else None
    if "@" not in a:
        return None
    local, domain = a.rsplit("@", 1)
    if not local or not all(0x21 <= ord(c) <= 0x7E and c != "@" for c in local):
        return None
    labels = domain.split(".")
    if len(labels) < 2 or not all(re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?", lb) for lb in labels):
        return None
    out = f"{local}@{domain.lower()}"
    return out if len(out.encode()) <= 255 else None


# --- T§5 --------------------------------------------------------------------------------------

def vrf_input(label: bytes, version: int) -> bytes:
    if len(label) > 255 or not 0 <= version <= 0xFFFFFFFF:
        raise ValueError("vrf-input")
    return u8(len(label)) + label + u32(version)


def index(vrf_pk: bytes, label: bytes, version: int, proof: bytes) -> bytes | None:
    beta = vrf.verify(vrf_pk, vrf_input(label, version), proof, validate=True)
    return None if beta is None else beta[:32]


def commitment(opening: bytes, label: bytes, version: int, value: bytes) -> bytes:
    if len(opening) != NC:
        raise ValueError("opening")
    if len(label) > 255 or not 0 <= version <= 0xFFFFFFFF:
        raise ValueError("label")
    cv = opening + u8(len(label)) + label + u32(version) + u32(len(value)) + value
    return hmac.new(KC, cv, hashlib.sha256).digest()


def prefix_leaf(idx: bytes, comm: bytes) -> bytes:
    return sha(b"\x02" + idx + comm)


def prefix_parent(left: bytes | None, right: bytes | None) -> bytes:
    return sha(b"\x03" + (left or ZERO) + (right or ZERO))


def _bit(key: bytes, i: int) -> int:
    return (key[i // 8] >> (7 - i % 8)) & 1


def prefix_root(leaves: dict, depth: int = 0) -> bytes:
    """A leaf sits as high as needed to separate it from the others ([KT] §3.3)."""
    if len(leaves) == 1:
        (k, c), = leaves.items()
        return prefix_leaf(k, c)
    left = {k: c for k, c in leaves.items() if _bit(k, depth) == 0}
    right = {k: c for k, c in leaves.items() if _bit(k, depth) == 1}
    return prefix_parent(prefix_root(left, depth + 1) if left else None, prefix_root(right, depth + 1) if right else None)


def log_leaf(ts_ms: int, prefix: bytes) -> bytes:
    return sha(u64(ts_ms) + prefix)


def log_root(leaves: list[bytes]) -> bytes:
    """A left-balanced tree; a parent hashes hashContent(left) ‖ hashContent(right) ([KT] §11.8)."""
    def go(lo, hi):
        if hi - lo == 1:
            return leaves[lo], True
        k = 1 << ((hi - lo - 1).bit_length() - 1)
        (lv, ll), (rv, rl) = go(lo, lo + k), go(lo + k, hi)
        return sha((b"\x00" if ll else b"\x01") + lv + (b"\x00" if rl else b"\x01") + rv), False
    return go(0, len(leaves))[0]


def configuration(c: dict) -> bytes:
    """Mode 1 per the KEYTRANS editors' copy: no leaf_public_key (spec-gap 104)."""
    return (u16(c["ciphersuite"]) + u8(c["mode"]) + u16(len(c["signature_public_key"])) + c["signature_public_key"]
            + u16(len(c["vrf_public_key"])) + c["vrf_public_key"]
            + u64(c["max_ahead"]) + u64(c["max_behind"]) + u64(c["reasonable_monitoring_window"])
            + (b"\x00" if c.get("maximum_lifetime") is None else b"\x01" + u64(c["maximum_lifetime"])))


def parse_configuration(b: bytes) -> dict:
    """Parse a mode-1 Configuration and apply T§2; raises ValueError with the error token."""
    pos = 0

    def take(n):
        nonlocal pos
        if pos + n > len(b):
            raise ValueError("malformed")
        out = b[pos:pos + n]
        pos += n
        return out

    suite = struct.unpack(">H", take(2))[0]
    mode = take(1)[0]
    if suite != SUITE:
        raise ValueError("unsupported-suite")
    if mode != MODE:
        raise ValueError("unsupported-mode")
    keys = [take(struct.unpack(">H", take(2))[0]) for _ in range(2)]
    ahead, behind, rmw = (struct.unpack(">Q", take(8))[0] for _ in range(3))
    flag = take(1)[0]
    if flag not in (0, 1):
        raise ValueError("malformed")
    life = struct.unpack(">Q", take(8))[0] if flag else None
    if pos != len(b):
        raise ValueError("malformed")
    # suite 0x0002 keys are 32 bytes; durations above 2^53−1 ms are refused (portable as JSON numbers)
    if any(len(k) != 32 for k in keys) or any(x > 2**53 - 1 for x in (ahead, behind, rmw, life or 0)):
        raise ValueError("malformed")
    return {"signature_public_key": keys[0].hex(), "vrf_public_key": keys[1].hex(),
            "max_ahead": ahead, "max_behind": behind, "reasonable_monitoring_window": rmw, "maximum_lifetime": life}


def tree_head_valid(config: bytes, tree_size: int, root: bytes, signature: bytes) -> bool:
    cfg = parse_configuration(config)
    tbs = config + u64(tree_size) + root
    return ed25519_verify(bytes.fromhex(cfg["signature_public_key"]), tbs, signature)


def _level(x):
    k = 0
    while (x >> k) & 1:
        k += 1
    return k


def bst_root(n):
    return (1 << (n.bit_length() - 1)) - 1


def frontier(n):
    def left(x):
        return x ^ (1 << (_level(x) - 1))

    def right(x):
        x ^= 3 << (_level(x) - 1)
        while x >= n:
            x = left(x)
        return x
    out = [bst_root(n)]
    while out[-1] != n - 1:
        out.append(right(out[-1]))
    return out


def base_ladder(t):
    out = []
    while True:
        v = (1 << len(out)) - 1
        out.append(v)
        if v > t:
            break
    lo, hi = out[-2], out[-1]
    while lo + 1 < hi:
        v = (lo + hi) // 2
        out.append(v)
        lo, hi = (v, hi) if v <= t else (lo, v)
    return out


# --- vectors -----------------------------------------------------------------------------------

def run(v: dict):
    i = v["input"]
    c = i["check"]
    h = bytes.fromhex
    try:
        if c == "alias":
            n = normalize_alias(i["alias"])
            return {"label": n} if n is not None else {"error": "not-an-alias"}
        if c == "vrf-input":
            return {"bytes": vrf_input(i["label"].encode(), i["version"]).hex()}
        if c == "vrf-verify":
            beta = vrf.verify(h(i["public_key"]), h(i["alpha"]), h(i["proof"]), validate=True)
            return {"valid": beta is not None, "beta": beta.hex() if beta else None}
        if c == "index":
            idx = index(h(i["public_key"]), i["label"].encode(), i["version"], h(i["proof"]))
            return {"index": idx.hex()} if idx else {"error": "vrf-invalid"}
        if c == "commitment":
            return {"commitment": commitment(h(i["opening"]), i["label"].encode(), i["version"], i["value"].encode()).hex()}
        if c == "commitment-raw":
            return {"commitment": hmac.new(KC, h(i["opening"]) + h(i["body"]), hashlib.sha256).hexdigest()}
        if c == "prefix-root":
            leaves = {h(x["index"]): h(x["commitment"]) for x in i["leaves"]}
            if len(leaves) != len(i["leaves"]) or not leaves or any(len(k) != 32 or len(x) != 32 for k, x in leaves.items()):
                return {"error": "malformed"}
            return {"root": prefix_root(leaves).hex()}
        if c == "prefix-parent":
            return {"hash": prefix_parent(h(i["left"]) if i["left"] else None, h(i["right"]) if i["right"] else None).hex()}
        if c == "log-root":
            if not i["entries"]:
                return {"error": "malformed"}
            return {"root": log_root([log_leaf(e["timestamp"], h(e["prefix_root"])) for e in i["entries"]]).hex()}
        if c == "configuration":
            return {"bytes": configuration({**i["config"], **{k: h(i["config"][k]) for k in
                                                             ("signature_public_key", "vrf_public_key")}}).hex()}
        if c == "configuration-accept":
            return {"config": parse_configuration(h(i["bytes"]))}
        if c == "tree-head":
            return {"valid": tree_head_valid(h(i["configuration"]), i["tree_size"], h(i["root"]), h(i["signature"]))}
        if c == "search-tree":
            return {"root": bst_root(i["n"]), "frontier": frontier(i["n"])}
        if c == "ladder":
            return {"ladder": base_ladder(i["version"])}
    except ValueError as e:
        return {"error": str(e)}
    raise KeyError(c)
