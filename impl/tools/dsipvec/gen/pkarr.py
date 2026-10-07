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
    out += carry_vectors()
    out += devices_vectors()
    out += store_vectors()
    return out


# --- publishing: carry and next-ts (spec-gap 105, decided 2026-10-05) ------------------------------------------

def _wire(name: str) -> bytes:
    return b"".join(bytes([len(x)]) + x.encode() for x in name.split(".") if x) + b"\x00"


def _rr(owner: bytes, rtype: int, rdata: bytes, ttl: int = 300, rclass: int = 1) -> bytes:
    return owner + struct.pack("!HHIH", rtype, rclass, ttl, len(rdata)) + rdata


def carry_vectors() -> list[dict]:
    """`check: "carry"`: expectations written from the records placed in each message."""
    out = []
    z = z32_encode(K.public)
    R = ["§8.5"]
    hdr = lambda n: struct.pack("!HHHHHH", 0, 0x8400, 0, n, 0, 0)  # noqa: E731
    dsip_owner = _wire(f"_dsip.{z}")
    zone_at = 12 + 6  # the zone label inside the first record's owner, which always starts at offset 12
    ptr_zone = struct.pack("!H", 0xC000 | zone_at)
    dsip_rr = _rr(dsip_owner, 16, txt("uri=wss://relay.example/dsip", "b=ws/1.0"))

    def cv(vid, desc, dns: bytes, want):
        out.append(vector(f"pkarr/carry-{vid}", "pkarr", desc, R, {}, {"check": "carry", "zone": z, "dns": dns.hex()}, want))

    def keep(name: str, rtype: int, rdata: bytes, ttl: int = 300):
        return {"name": _wire(name).hex(), "type": rtype, "ttl": ttl, "rdata": rdata.hex()}

    iroh = txt("relay=https://iroh.example")
    a, aaaa = bytes([192, 0, 2, 7]), bytes(15) + b"\x01"
    cv("verbatim-and-dsip-replaced", "TXT, A and AAAA are kept as they are; the _dsip records are the publisher's to replace.",
       hdr(4) + dsip_rr + _rr(b"\x05_iroh" + ptr_zone, 16, iroh) + _rr(ptr_zone, 1, a) + _rr(ptr_zone, 28, aaaa),
       {"keep": [keep(f"_iroh.{z}", 16, iroh), keep(z, 1, a), keep(z, 28, aaaa)]})
    cv("cname-expanded", "A CNAME whose target is compressed into the zone name is re-encoded with the name expanded.",
       hdr(2) + dsip_rr + _rr(b"\x03www" + ptr_zone, 5, b"\x04edge" + ptr_zone),
       {"keep": [keep(f"www.{z}", 5, _wire(f"edge.{z}"))]})
    cv("mx-expanded", "MX: the preference is kept, the exchange name expanded.",
       hdr(2) + dsip_rr + _rr(ptr_zone, 15, b"\x00\x0a\x04mail" + ptr_zone),
       {"keep": [keep(z, 15, b"\x00\x0a" + _wire(f"mail.{z}"))]})
    soa_tail = struct.pack("!IIIII", 1, 7200, 3600, 1209600, 300)
    cv("soa-expanded", "SOA: both names expanded, the 20 bytes of counters kept.",
       hdr(2) + dsip_rr + _rr(ptr_zone, 6, b"\x02ns" + ptr_zone + b"\x0ahostmaster" + ptr_zone + soa_tail),
       {"keep": [keep(z, 6, _wire(f"ns.{z}") + _wire(f"hostmaster.{z}") + soa_tail)]})
    svcb = b"\x00\x01" + _wire(f"svc.{z}") + b"\x00\x01\x00\x03\x02h2"
    cv("svcb-verbatim", "SVCB is not an RFC 1035 type: compression is forbidden in it (RFC 3597 §4), so it is copied as is.",
       hdr(2) + dsip_rr + _rr(ptr_zone, 64, svcb), {"keep": [keep(z, 64, svcb)]})
    cv("unknown-type-verbatim", "A private-use type is copied as is.",
       hdr(2) + dsip_rr + _rr(ptr_zone, 65280, b"\xc0\x12opaque"), {"keep": [keep(z, 65280, b"\xc0\x12opaque")]})
    cv("dsip-owner-case-insensitive", "An owner of _DSIP.<zone> is the DSIP name too, whatever its case.",
       hdr(2) + dsip_rr + _rr(b"\x05_DSIP" + ptr_zone, 16, txt("old")), {"keep": []})
    cv("dsip-devices-and-delegation-replaced", "The _dsip-devices and _dsip-delegation records are the publisher's to "
       "replace too (§9.1); a deeper name under them is not.",
       hdr(4) + dsip_rr + _rr(b"\x0d_dsip-devices" + ptr_zone, 16, txt("dev=x")) + _rr(b"\x10_dsip-delegation" + ptr_zone, 16, txt("y"))
       + _rr(b"\x01x\x0d_dsip-devices" + ptr_zone, 16, iroh), {"keep": [keep(f"x._dsip-devices.{z}", 16, iroh)]})
    cv("class-not-in-skipped", "A record of class CH (3) is not carried.",
       hdr(2) + dsip_rr + _rr(b"\x05_iroh" + ptr_zone, 16, iroh, rclass=3), {"keep": []})
    cv("case-kept", "Label bytes keep their case in the carried name.",
       hdr(2) + dsip_rr + _rr(b"\x03WwW" + ptr_zone, 1, a), {"keep": [keep(f"WwW.{z}", 1, a)]})
    cv("rdata-pointer-forward", "A name in a CNAME's rdata pointing forward is malformed.",
       hdr(2) + dsip_rr + _rr(ptr_zone, 5, b"\xc3\xff"), {"error": "malformed"})
    cv("rdata-trailing-bytes", "A CNAME rdata holding more than its one name is malformed.",
       hdr(2) + dsip_rr + _rr(ptr_zone, 5, b"\x04edge" + ptr_zone + b"\x00"), {"error": "malformed"})
    cv("rdata-name-past-rdlength", "A CNAME's inline name running past its rdlength is malformed.",
       hdr(2) + dsip_rr + _rr(ptr_zone, 5, b"\x04edg"), {"error": "malformed"})

    def tv(vid, desc, inp, want):
        out.append(vector(f"pkarr/next-ts-{vid}", "pkarr", desc, R, {}, {"check": "next-ts", **inp}, {"ts": want}))
    tv("clock-ahead", "The clock is past the previous timestamp: sign the clock.", {"clock": TS + 10, "previous": TS}, TS + 10)
    tv("clock-stepped-back", "The clock stepped back: previous + 1, ahead of the clock — the one case allowed.",
       {"clock": TS - 5_000_000, "previous": TS}, TS + 1)
    tv("clock-equal", "Equal to the previous timestamp: previous + 1.", {"clock": TS, "previous": TS}, TS + 1)
    tv("first", "No previous packet: the clock.", {"clock": TS}, TS)
    out.append(vector("pkarr/next-ts-exhausted", "pkarr", "previous + 1 would exceed 2^53−1, which every reader rejects: sign nothing.",
                      R, {}, {"check": "next-ts", "clock": TS, "previous": 2**53 - 1}, {"error": "exhausted"}))
    out.append(vector("pkarr/carry-not-hex", "pkarr", "dns that is not hex is malformed.", R, {},
                      {"check": "carry", "zone": z32_encode(K.public), "dns": "zz"}, {"error": "malformed"}))
    return out


# --- multi-device identities: pointer + device zones (§9.1; spec-gap 105 option (b)) ---------------------------

def devices_vectors() -> list[dict]:
    from .. import envelope as E
    from .. import fixtures as F
    out = []
    R = ["§8.5", "§7.4"]
    z = z32_encode(K.public)
    PHONE, LAPTOP = keypair_from_seed_name("pkarr-alice-phone"), keypair_from_seed_name("pkarr-alice-laptop")
    dphone, dlaptop = did_key(PHONE.public), did_key(LAPTOP.public)
    hdr = lambda n: struct.pack("!HHHHHH", 0, 0x8400, 0, n, 0, 0)  # noqa: E731

    def signed_by(key, dns_msg, ts=TS):
        return (key.sign(bep44_signable(ts, dns_msg)) + struct.pack("!Q", ts) + dns_msg).hex()

    def pointer(devs, ttl=86_400, ts=TS, signer=None):
        recs = b"".join(_rr(_wire(f"_dsip-devices.{z}"), 16, txt(f"dev={d}"), ttl=ttl) for d in devs)
        return signed_by(signer or K, hdr(len(devs)) + recs, ts)

    def compact(d):
        return f"{d['protected']}.{d['payload']}.{d['signature']}"

    def deleg(dev_did, **kw):
        return compact(F.make_delegation(K, DID, dev_did, issued_at=kw.pop("issued_at", NOW - 86_400),
                                         expires_at=kw.pop("expires_at", NOW + 30 * 86_400), signer_kid=K.kid, **kw))

    def device_payload(key, uri, delegation=None, extra_deleg=0, ttl=1800, signer=None):
        dz = z32_encode(key.public)
        recs = [_rr(_wire(f"_dsip.{dz}"), 16, txt(f"uri={uri}", "b=ws/1.0"), ttl=ttl)]
        if delegation is not None:
            b = delegation.encode()
            strings = b"".join(bytes([len(b[i:i + 255])]) + b[i:i + 255] for i in range(0, len(b), 255))
            recs.append(_rr(_wire(f"_dsip-delegation.{dz}"), 16, strings, ttl=ttl))
            for _ in range(extra_deleg):  # a short second record: two full delegations would not fit in 1,000 bytes
                recs.append(_rr(_wire(f"_dsip-delegation.{dz}"), 16, txt("x"), ttl=ttl))
        return signed_by(signer or key, hdr(len(recs)) + b"".join(recs))

    def dv(vid, desc, payload, devs, want, revocations=None, now=NOW):
        inp = {"check": "devices", "did": DID, "payload": payload, "devices": devs, "now": now}
        if revocations is not None:
            inp["revocations"] = revocations
        out.append(vector(f"pkarr/devices-{vid}", "pkarr", desc, R, {}, inp, want))

    P_URI, L_URI = "wss://relay-a.example/dsip", "wss://relay-b.example/dsip"
    ep = lambda u: [{"uri": u, "bindings": ["ws/1.0"]}]  # noqa: E731
    hint_exp = TS // 1_000_000 + 1800
    ptr_exp = TS // 1_000_000 + 86_400
    ok = lambda d, u, exp=hint_exp: {"device": d, "outcome": "hint", "endpoints": ep(u), "expires_at": exp}  # noqa: E731
    rejected = lambda d, r: {"device": d, "outcome": "rejected", "reason": r}  # noqa: E731
    both = {dphone: device_payload(PHONE, P_URI, deleg(dphone)), dlaptop: device_payload(LAPTOP, L_URI, deleg(dlaptop))}
    head = {"outcome": "devices", "seq": TS, "expires_at": ptr_exp}

    dv("two-devices", "The identity's pointer names two devices; each device's own hint, with its delegation, gives its relay.",
       pointer([dphone, dlaptop]), both, {**head, "devices": [ok(dphone, P_URI), ok(dlaptop, L_URI)]})
    dv("pointer-seven-days", "A pointer may live 7 days (604,800 s): the identity key stays offline.",
       pointer([dphone], ttl=604_800), {dphone: both[dphone]},
       {**head, "expires_at": TS // 1_000_000 + 604_800, "devices": [ok(dphone, P_URI)]})
    dv("delegation-expires-first", "A device is usable until the earlier of its hint's expiry and its delegation's.",
       pointer([dphone]), {dphone: device_payload(PHONE, P_URI, deleg(dphone, expires_at=NOW + 100))},
       {**head, "devices": [ok(dphone, P_URI, NOW + 100)]})
    dv("device-unavailable", "No payload could be fetched for a listed device.", pointer([dphone, dlaptop]), {dphone: both[dphone]},
       {**head, "devices": [ok(dphone, P_URI), rejected(dlaptop, "unavailable")]})
    dv("device-hint-bad-signature", "A device zone not signed by that device's key.", pointer([dphone]),
       {dphone: device_payload(PHONE, P_URI, deleg(dphone), signer=LAPTOP)}, {**head, "devices": [rejected(dphone, "signature")]})
    dv("delegation-missing", "A device hint without its delegation record.", pointer([dphone]),
       {dphone: device_payload(PHONE, P_URI)}, {**head, "devices": [rejected(dphone, "delegation-missing")]})
    dv("delegation-twice", "Two delegation records (the second a short one, so the packet still fits).", pointer([dphone]),
       {dphone: device_payload(PHONE, P_URI, deleg(dphone), extra_deleg=1)}, {**head, "devices": [rejected(dphone, "delegation-invalid")]})
    dv("delegation-for-another-device", "The phone's zone carries the laptop's delegation.", pointer([dphone]),
       {dphone: device_payload(PHONE, P_URI, deleg(dlaptop))}, {**head, "devices": [rejected(dphone, "delegation-invalid")]})
    foreign = compact(F.make_delegation(OTHER, DID, dphone, signer_kid=OTHER.kid))
    dv("delegation-not-by-identity", "A delegation signed by another key than the identity's.", pointer([dphone]),
       {dphone: device_payload(PHONE, P_URI, foreign)}, {**head, "devices": [rejected(dphone, "delegation-invalid")]})
    dv("delegation-no-signaling", "A delegation without dsip.signaling.", pointer([dphone]),
       {dphone: device_payload(PHONE, P_URI, deleg(dphone, capabilities=("dsip.messaging",)))},
       {**head, "devices": [rejected(dphone, "delegation-capability")]})
    dv("delegation-expired", "An expired delegation.", pointer([dphone]),
       {dphone: device_payload(PHONE, P_URI, deleg(dphone, issued_at=NOW - 90 * 86_400, expires_at=NOW - 1))},
       {**head, "devices": [rejected(dphone, "delegation-expired")]})
    rev = E.sign({"dsip": F.VERSION, "type": "delegation-revocation", "id": "01M3S8JR0000000000000REVK1", "from": DID, "subject": DID,
                  "device": dlaptop, "revoked_at": NOW - 60, "reason": "lost", "issued_at": NOW - 60, "expires_at": NOW + 240}, K, K.kid)
    dv("device-revoked", "A revocation the reader holds stops the laptop counting, though the pointer still lists it (§9.1: "
       "bounded, not immediate).", pointer([dphone, dlaptop]), both,
       {**head, "devices": [ok(dphone, P_URI), rejected(dlaptop, "delegation-revoked")]}, revocations=[compact(rev)])
    dv("device-null-unavailable", "A device whose payload is null is unavailable.", pointer([dphone]), {dphone: None},
       {**head, "devices": [rejected(dphone, "unavailable")]})
    dz = z32_encode(PHONE.public)
    broken = signed_by(PHONE, hdr(2) + _rr(_wire(f"_dsip.{dz}"), 16, txt(f"uri={P_URI}", "b=ws/1.0"))
                       + _rr(_wire(f"_dsip-delegation.{dz}"), 16, b"\x09abc"))
    dv("delegation-record-unsplittable", "A delegation record whose data does not split into character-strings: that device "
       "is delegation-invalid, the others still resolve.", pointer([dphone, dlaptop]), {dphone: broken, dlaptop: both[dlaptop]},
       {**head, "devices": [rejected(dphone, "delegation-invalid"), ok(dlaptop, L_URI)]})
    dv("duplicate-listed-once", "A device listed twice is resolved once.", pointer([dphone, dphone]), {dphone: both[dphone]},
       {**head, "devices": [ok(dphone, P_URI)]})
    for vid, desc, payload, want in [
        ("pointer-signature", "A pointer not signed by the identity key.", pointer([dphone], signer=OTHER), "signature"),
        ("pointer-ttl-too-long", "A pointer TTL above 604,800 s.", pointer([dphone], ttl=604_801), "ttl-too-long"),
        ("pointer-expired", "An expired pointer.", pointer([dphone], ttl=30), "expired"),
        ("pointer-bad-dev", "A dev= value that is not a did:key.", signed_by(K, hdr(1) + _rr(_wire(f"_dsip-devices.{z}"), 16,
         txt("dev=did:web:phone.example"))), "bad-pointer"),
        ("pointer-none", "A zone with no _dsip-devices records.", signed_by(K, hdr(1) + _rr(_wire(f"_dsip.{z}"), 16,
         txt("uri=wss://relay.example/dsip", "b=ws/1.0"))), "no-devices"),
    ]:
        dv(vid, desc, payload, {}, {"outcome": "rejected", "reason": want})
    return out


def store_vectors() -> list[dict]:
    """`check: "store"`: a node's verify-before-store for PUT /<z32> (v0.11, profile §10)."""
    out = []
    z = z32_encode(K.public)
    K2 = keypair_from_seed_name("pkarr-bob")
    refs = ["§8.3", "§8.5"]

    def sv(vid, desc, key, pay, held, expect):
        out.append(vector(f"pkarr/store-{vid}", "pkarr", desc, refs, {},
                          {"check": "store", "key": key, "payload": pay, "held": held, "now": NOW}, expect))
    stored, kept = {"outcome": "stored"}, lambda r: {"outcome": "kept", "reason": r}  # noqa: E731
    p1 = payload([EP])
    p2 = payload([EP], ts=TS + 1_000_000)
    p1b = payload([("_dsip", 16, 1800, txt("uri=wss://other.example/dsip", "b=ws/1.0"))])  # same ts, other content
    other_app = payload([("@", 1, 300, bytes([192, 0, 2, 7]))])
    sv("first", "Nothing held: a verified packet is stored.", z, p1, None, stored)
    sv("newer", "A higher timestamp replaces the held packet.", z, p2, p1, stored)
    sv("same", "The same bytes again: kept, and answered as stored (idempotent).", z, p1, p1, kept("same"))
    sv("older", "A lower timestamp is kept out (§8.3).", z, p1, p2, kept("older"))
    sv("conflict", "An equal timestamp with other content: the held one stays (§8.3).", z, p1b, p1, kept("conflict"))
    sv("other-application", "A packet with no _dsip records (another Pkarr application's) is stored: the node serves "
       "every application.", z, other_app, None, stored)
    sv("expired-dsip-still-stored", "A _dsip packet whose hint has expired is still stored; readers judge content.", z,
       payload([EP], ts=(NOW - 7200) * 1_000_000), None, stored)
    sv("wrong-key", "A packet signed by another key than the path's.", z, payload([EP], signer=K2), None,
       rejected("signature"))
    sv("future", "A timestamp more than 300 s ahead.", z, payload([EP], ts=(NOW + 301) * 1_000_000), None, rejected("future"))
    sv("short", "Fewer than 72 bytes.", z, "00" * 71, None, rejected("malformed"))
    sv("not-hex", "A payload that is not hex.", z, "zz", None, rejected("malformed"))
    sv("bad-dns", "A packet whose DNS message does not parse.", z, (lambda d: (K.sign(bep44_signable(TS, d)) +
       struct.pack("!Q", TS) + d).hex())(b"\x00" * 11), None, rejected("malformed"))
    last = z[-1]
    noncanon = z[:-1] + next(c for c in "ybndrfg8ejkmcpqxot1uwisza345h769" if c != last and
                              "ybndrfg8ejkmcpqxot1uwisza345h769".index(c) >> 4 == "ybndrfg8ejkmcpqxot1uwisza345h769".index(last) >> 4)
    sv("key-non-canonical", "A key whose padding bits are not zero (one of 16 spellings of the key).", noncanon, p1,
       None, {"outcome": "rejected", "reason": "bad-key"})
    sv("key-uppercase", "An uppercase key.", z.upper(), p1, None, {"outcome": "rejected", "reason": "bad-key"})
    sv("key-short", "A key of 51 characters.", z[:-1], p1, None, {"outcome": "rejected", "reason": "bad-key"})
    sv("rejected-before-held", "A bad signature is rejected whatever is held.", z, payload([EP], ts=TS + 9_000_000, signer=K2),
       p1, rejected("signature"))
    return out
