"""`pkarr/` vectors — reachability hints on Pkarr (DHT Hints Profile §9; spec-gap 105).

Payloads are built here with deterministic keys; each expected hint is written from what was published (the
endpoints, the timestamp, the TTLs), and each negative breaks one rule. BEP 44's own published test vectors are
included, and the payloads are checked against the pkarr crate (spec-gap 105).
"""
from __future__ import annotations

import struct

from ..crypto import keypair_from_seed_name
from ..pkarr import bep44_signable, did_key, z32_encode
from .common import vector

REFS = ["§8.5", "§8.3"]
NOW = 1_790_000_000  # resolver clock, Unix seconds
TS = NOW * 1_000_000 - 60_000_000  # published a minute ago, µs
K = keypair_from_seed_name("pkarr-alice")
OTHER = keypair_from_seed_name("pkarr-bob")
DID = did_key(K.public)
# BEP 44 (bittorrent.org/beps/bep_0044.html) test vectors
BEP44_PK = "77ff84905a91936367c01360803104f92432fcd904a43511876df5cdf3e7e548"
BEP44_SIG = ("305ac8aeb6c9c151fa120f120ea2cfb923564e11552d06a5d856091e5e853cff"
             "1260d3f39e4999684aa92eb73ffd136e6f4f3ecbfda0ce53a1608ecd7ae21f01")
BEP44_SIG_SALT = ("6834284b6b24c3204eb2fea824d82f88883a3d95e8b4a21b8c0ded553d17d17d"
                  "df9a8a7104b1258f30bed3787e6cb896fca78c58f8e03b5f18f14951a87d9a08")


def name(full: str, buf: bytearray, table: dict | None) -> None:
    labels = [x for x in full.split(".") if x]
    for i in range(len(labels)):
        suffix = ".".join(labels[i:]).lower()
        if table is not None and suffix in table:
            buf += struct.pack("!H", 0xC000 | table[suffix])
            return
        if table is not None and len(buf) < 0x4000:
            table[suffix] = len(buf)
        lb = labels[i].encode()
        buf.append(len(lb))
        buf += lb
    buf.append(0)


def txt(*strings: str) -> bytes:
    return b"".join(bytes([len(s.encode())]) + s.encode() for s in strings)


def dns(records, key=K, compress=True) -> bytes:
    """records: (owner relative to the zone, or absolute with a trailing dot; type; ttl; rdata)."""
    z = z32_encode(key.public)
    buf = bytearray(struct.pack("!HHHHHH", 0, 0x8000, 0, len(records), 0, 0))
    table = {} if compress else None
    for owner, rtype, ttl, rdata in records:
        full = owner[:-1] if owner.endswith(".") else (z if owner == "@" else f"{owner}.{z}")
        name(full, buf, table)
        buf += struct.pack("!HHIH", rtype, 1, ttl, len(rdata)) + rdata
    return bytes(buf)


def payload(records, ts=TS, key=K, compress=True, signer=None) -> str:
    d = dns(records, key, compress)
    sig = (signer or key).sign(bep44_signable(ts, d))
    return (sig + struct.pack("!Q", ts) + d).hex()


EP = ("_dsip", 16, 1800, txt("uri=wss://relay.example/dsip", "b=ws/1.0"))


def single_label_owner() -> bytes:
    lb = b"_dsip." + z32_encode(K.public).encode()
    return bytes([len(lb)]) + lb + b"\x00"


def two_label_owner() -> bytes:
    z = z32_encode(K.public).encode()
    return b"\x05_dsip" + bytes([len(z)]) + z + b"\x00"


def payload_raw(records, ts=TS) -> str:
    """records: (owner name in wire form, TXT rdata), uncompressed, TTL 1800."""
    buf = bytearray(struct.pack("!HHHHHH", 0, 0x8000, 0, len(records), 0, 0))
    for owner, rdata in records:
        buf += owner + struct.pack("!HHIH", 16, 1, 1800, len(rdata)) + rdata
    d = bytes(buf)
    return (K.sign(bep44_signable(ts, d)) + struct.pack("!Q", ts) + d).hex()


def pv(vid, desc, inp, expect, refs=None):
    return vector(f"pkarr/{vid}", "pkarr", desc, refs or REFS, {}, inp, expect)


def hint(endpoints, ttl=1800, ts=TS):
    issued = ts // 1_000_000
    return {"outcome": "hint", "subject": DID, "seq": ts, "issued_at": issued, "expires_at": issued + ttl, "endpoints": endpoints}


def rejected(r):
    return {"outcome": "rejected", "reason": r}


def vectors() -> list[dict]:
    out = []
    E1 = {"uri": "wss://relay.example/dsip", "bindings": ["ws/1.0"]}
    # --- valid hints -------------------------------------------------------------------------------
    out.append(pv("one-endpoint", "One `_dsip` TXT record: the relay URI and binding. Expiry = signed time + TTL.",
                  {"check": "hint", "did": DID, "payload": payload([EP]), "now": NOW}, hint([E1])))
    two = [EP, ("_dsip", 16, 900, txt("uri=wss://backup.example/dsip", "b=ws/1.0", "svc=DSIPSignaling"))]
    out.append(pv("two-endpoints-min-ttl", "Two endpoints in record order; the expiry uses the smaller TTL; svc= is carried.",
                  {"check": "hint", "did": DID, "payload": payload(two), "now": NOW},
                  hint([E1, {"uri": "wss://backup.example/dsip", "bindings": ["ws/1.0"], "service": "DSIPSignaling"}], ttl=900)))
    out.append(pv("uncompressed-accepted", "An uncompressed DNS packet parses (Pkarr: publishers compress, readers accept both).",
                  {"check": "hint", "did": DID, "payload": payload(two, compress=False), "now": NOW},
                  hint([E1, {"uri": "wss://backup.example/dsip", "bindings": ["ws/1.0"], "service": "DSIPSignaling"}], ttl=900)))
    foreign = [("@", 16, 300, txt("pubky=homeserver")), ("_iroh", 16, 300, txt("relay=https://iroh.example")), EP]
    out.append(pv("foreign-records-ignored", "Other records of the same key's zone (Pubky, iroh) are not DSIP's and are ignored.",
                  {"check": "hint", "did": DID, "payload": payload(foreign), "now": NOW}, hint([E1])))
    out.append(pv("out-of-zone-record-ignored", "A record named outside the key's zone is ignored, not used.",
                  {"check": "hint", "did": DID, "payload": payload([("_dsip.example.com.", 16, 1800, txt("uri=wss://evil.example/dsip", "b=ws/1.0")), EP]),
                   "now": NOW}, hint([E1])))
    out.append(pv("unknown-key-ignored", "An unknown key=value string in the record is ignored (room to grow).",
                  {"check": "hint", "did": DID, "payload": payload([("_dsip", 16, 1800, txt("uri=wss://relay.example/dsip", "b=ws/1.0", "prio=1"))]),
                   "now": NOW}, hint([E1])))
    out.append(pv("owner-name-case-insensitive", "Owner names compare case-insensitively.",
                  {"check": "hint", "did": DID, "payload": payload([("_DSIP", 16, 1800, EP[3])]), "now": NOW}, hint([E1])))
    out.append(pv("timestamp-within-tolerance", "A timestamp 4 minutes ahead of the reader's clock.",
                  {"check": "hint", "did": DID, "payload": payload([EP], ts=(NOW + 240) * 1_000_000), "now": NOW},
                  hint([E1], ts=(NOW + 240) * 1_000_000)))
    # --- rejections --------------------------------------------------------------------------------
    out.append(pv("not-did-key", "Pkarr hints are for did:key subjects.", {"check": "hint", "did": "did:web:example.com",
                  "payload": payload([EP]), "now": NOW}, rejected("not-did-key")))
    out.append(pv("signed-by-another-key", "A payload signed by a different key than the DID's.",
                  {"check": "hint", "did": DID, "payload": payload([EP], signer=OTHER), "now": NOW}, rejected("signature")))
    p = bytearray.fromhex(payload([EP]))
    p[64 + 7] ^= 1
    out.append(pv("timestamp-tampered", "The timestamp changed after signing (it is the signed seq).",
                  {"check": "hint", "did": DID, "payload": p.hex(), "now": NOW}, rejected("signature")))
    out.append(pv("timestamp-in-future", "A timestamp 6 minutes ahead: Pkarr accepts it, DSIP does not.",
                  {"check": "hint", "did": DID, "payload": payload([EP], ts=(NOW + 360) * 1_000_000), "now": NOW}, rejected("future")))
    out.append(pv("expired", "Published 31 minutes ago with a 30-minute TTL.",
                  {"check": "hint", "did": DID, "payload": payload([EP], ts=(NOW - 1860) * 1_000_000), "now": NOW}, rejected("expired")))
    out.append(pv("ttl-too-long", "A TTL above 3600 s (a hint's lifetime cap, §12.9; spec-gap 96).",
                  {"check": "hint", "did": DID, "payload": payload([("_dsip", 16, 7200, EP[3])]), "now": NOW}, rejected("ttl-too-long")))
    out.append(pv("no-dsip-records", "A packet with no `_dsip` TXT record.",
                  {"check": "hint", "did": DID, "payload": payload([("@", 16, 300, txt("pubky=homeserver"))]), "now": NOW}, rejected("no-endpoints")))
    for vid, strings, why in [("uri-not-wss", ("uri=https://relay.example/dsip", "b=ws/1.0"), "A URI that is not wss://."),
                              ("two-uris", ("uri=wss://a.example/dsip", "uri=wss://b.example/dsip", "b=ws/1.0"), "Two uri= in one record."),
                              ("no-binding", ("uri=wss://relay.example/dsip",), "No b= binding."),
                              ("string-without-equals", ("uri=wss://relay.example/dsip", "b=ws/1.0", "junk"), "A string that is not key=value.")]:
        out.append(pv(f"endpoint-{vid}", why, {"check": "hint", "did": DID, "payload": payload([("_dsip", 16, 1800, txt(*strings))]), "now": NOW},
                      rejected("bad-endpoint")))
    out.append(pv("owner-single-label-with-dot", "A single label `_dsip.<z32>` (one label containing a dot) is not the two labels "
                  "`_dsip` and `<z32>`: ignored, so no endpoints.",
                  {"check": "hint", "did": DID, "payload": payload_raw([(single_label_owner(), EP[3])]), "now": NOW}, rejected("no-endpoints")))
    out.append(pv("framing-checked-before-content", "A DSIP record with a bad string first and broken framing later: framing is "
                  "checked first.",
                  {"check": "hint", "did": DID, "payload": payload_raw([(two_label_owner(), txt("junk") + bytes([40]) + b"short")]),
                   "now": NOW}, rejected("malformed")))
    out.append(pv("timestamp-beyond-2p53", "A timestamp above 2^53−1 µs (exact JSON integers).",
                  {"check": "hint", "did": DID, "payload": payload([EP], ts=2**53), "now": 2**53 // 1_000_000}, rejected("malformed")))
    out.append(pv("payload-not-hex", "A payload that is not hex.", {"check": "hint", "did": DID, "payload": "zz" * 80, "now": NOW},
                  rejected("malformed")))
    good = bytes.fromhex(payload([EP]))
    out.append(pv("payload-too-short", "A payload shorter than signature and timestamp.", {"check": "hint", "did": DID,
                  "payload": good[:71].hex(), "now": NOW}, rejected("malformed")))
    d = dns([EP])[:-3]
    out.append(pv("dns-truncated", "A DNS packet cut inside its record (signed as is).",
                  {"check": "hint", "did": DID, "payload": (K.sign(bep44_signable(TS, d)) + struct.pack("!Q", TS) + d).hex(), "now": NOW},
                  rejected("malformed")))
    d = bytearray(dns([EP, ("_dsip", 16, 1800, EP[3])]))
    i = d.index(b"\xc0", 12)
    d[i + 1] = len(d) - 2  # a compression pointer that points forwards
    d = bytes(d)
    out.append(pv("dns-forward-pointer", "A compression pointer that does not point backwards.",
                  {"check": "hint", "did": DID, "payload": (K.sign(bep44_signable(TS, d)) + struct.pack("!Q", TS) + d).hex(), "now": NOW},
                  rejected("malformed")))
    # --- §8.3 between two payloads -----------------------------------------------------------------
    older = payload([EP], ts=TS - 600_000_000)
    newer = payload([("_dsip", 16, 1800, txt("uri=wss://new.example/dsip", "b=ws/1.0"))])
    out.append(pv("select-newer-wins", "§8.3: the higher timestamp (seq) wins.",
                  {"check": "select", "did": DID, "payload": newer, "held": older, "now": NOW}, {"winner": "input", "conflict": "newer-seq"}))
    out.append(pv("select-older-loses", "§8.3: a lower timestamp is discarded.",
                  {"check": "select", "did": DID, "payload": older, "held": newer, "now": NOW}, {"winner": "held", "conflict": "older-seq"}))
    out.append(pv("select-identical", "§8.3: the identical payload again is a no-op.",
                  {"check": "select", "did": DID, "payload": newer, "held": newer, "now": NOW}, {"winner": "held", "conflict": "none"}))
    same_ts = payload([("_dsip", 16, 1800, txt("uri=wss://other.example/dsip", "b=ws/1.0"))])
    out.append(pv("select-same-seq-different", "§8.3: the same timestamp with different content keeps the held one and warns "
                  "(not Pkarr's \"larger packet wins\").",
                  {"check": "select", "did": DID, "payload": same_ts, "held": newer, "now": NOW}, {"winner": "held", "conflict": "same-seq-live"}))
    out.append(pv("select-held-expired", "A held hint that has expired is absent: the input wins.",
                  {"check": "select", "did": DID, "payload": newer, "held": payload([EP], ts=(NOW - 3000) * 1_000_000), "now": NOW},
                  {"winner": "input", "conflict": "none"}))
    # --- BEP 44 and z-base-32 (the spec's own vectors; by hand) ------------------------------------
    out.append(pv("bep44-signable", "BEP 44's signed buffer for seq 1, value \"Hello World!\".",
                  {"check": "bep44-signable", "seq": 1, "value": b"Hello World!".hex(), "salt": None},
                  {"bytes": b"3:seqi1e1:v12:Hello World!".hex()}, ["§8.5"]))
    out.append(pv("bep44-signable-salt", "BEP 44's signed buffer with salt \"foobar\".",
                  {"check": "bep44-signable", "seq": 1, "value": b"Hello World!".hex(), "salt": b"foobar".hex()},
                  {"bytes": b"4:salt6:foobar3:seqi1e1:v12:Hello World!".hex()}, ["§8.5"]))
    out.append(pv("bep44-test-vector", "BEP 44's mutable test vector verifies.",
                  {"check": "bep44-verify", "public_key": BEP44_PK, "seq": 1, "value": b"Hello World!".hex(), "salt": None,
                   "signature": BEP44_SIG}, {"valid": True}, ["§8.5"]))
    out.append(pv("bep44-test-vector-salt", "BEP 44's salted test vector verifies.",
                  {"check": "bep44-verify", "public_key": BEP44_PK, "seq": 1, "value": b"Hello World!".hex(), "salt": b"foobar".hex(),
                   "signature": BEP44_SIG_SALT}, {"valid": True}, ["§8.5"]))
    out.append(pv("bep44-test-vector-wrong-seq", "The same signature checked against seq 2.",
                  {"check": "bep44-verify", "public_key": BEP44_PK, "seq": 2, "value": b"Hello World!".hex(), "salt": None,
                   "signature": BEP44_SIG}, {"valid": False}, ["§8.5"]))
    rfc_pk = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    out.append(pv("z32-encode", "The RFC 8032 test-1 key in z-base-32 (as the pkarr crate writes it).", {"check": "z32-encode", "key": rfc_pk},
                  {"z32": "47pjoycnsrfmxikm95jh13y88e8qnhzu5kungjpxyepgt7a8krpy"}, ["§8.5"]))
    out.append(pv("z32-decode", "…and back.", {"check": "z32-decode", "z32": "47pjoycnsrfmxikm95jh13y88e8qnhzu5kungjpxyepgt7a8krpy"},
                  {"key": rfc_pk}, ["§8.5"]))
    out.append(pv("z32-non-canonical", "The same key with padding bits set: Pkarr accepts it, DSIP does not.",
                  {"check": "z32-decode", "z32": "47pjoycnsrfmxikm95jh13y88e8qnhzu5kungjpxyepgt7a8krpb"}, rejected("non-canonical"), ["§8.5"]))
    out.append(pv("z32-bad-length", "51 characters.", {"check": "z32-decode", "z32": "47pjoycnsrfmxikm95jh13y88e8qnhzu5kungjpxyepgt7a8krp"},
                  rejected("malformed"), ["§8.5"]))
    return out
