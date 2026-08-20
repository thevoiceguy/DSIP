"""DHT reachability-hint record vectors (spec §8.1, §8.3, §8.5; plan §10.3).

A hint record is a DSIP-JOSE envelope whose payload is a `reachability-hint`.
It is never authoritative: verification is against the subject DID (or a
delegation), and §8.3 conflict rules decide between live records.
"""
from __future__ import annotations

from .. import fixtures as F
from .. import envelope as E
from ..crypto import b64url_decode, b64url_encode
from .common import NOW, signed, default_context, vector, accept, reject, uid

ALICE, APH = F.did("alice"), F.did("alice-phone")


def hint(label: str, subject: str, frm: str, seq: int, at: int = NOW, ttl: int = 3600, uri="wss://relay.example.com/dsip") -> dict:
    return {"dsip": F.VERSION_TRANSPORT, "type": "reachability-hint", "id": uid(label, at), "from": frm,
            "subject": subject, "endpoints": [{"uri": uri, "bindings": ["ws/1.0"]}], "seq": seq,
            "issued_at": at, "expires_at": at + ttl}


def dv(vid, desc, refs, env, expect, existing=None, ctx=None):
    context = ctx or default_context()
    if existing is not None:
        context["existing"] = existing
    return vector(f"dht/{vid}", "dht", desc, refs, context, {"envelope": env}, expect)


def vectors() -> list[dict]:
    out = []
    h1 = signed(hint("h1", ALICE, ALICE, 1), "alice")
    out.append(dv("valid-self-signed-did-key", "Hint for alice signed by alice's own did:key — zero external resolution.",
                  ["§8.3", "§8.5"], h1, accept(type="reachability-hint", signer=ALICE, identity=ALICE, winner="input", conflict="none")))
    h1_dev = signed(hint("h1d", ALICE, ALICE, 1, at=NOW - 60), "alice-phone")
    out.append(dv("valid-delegated-device", "Hint for alice signed by alice-phone under a live delegation.", ["§8.3", "§7.4"],
                  h1_dev, accept(type="reachability-hint", signer=APH, identity=ALICE, winner="input", conflict="none")))
    raw = b64url_decode(h1["payload"]).decode().replace("relay.example.com", "evil.example.com")
    out.append(dv("tampered-endpoint", "Endpoint URI altered after signing.", ["§8.3"],
                  {**h1, "payload": b64url_encode(raw.encode())}, reject("signature-invalid")))
    out.append(dv("non-delegated-signer", "mallory publishes a hint for alice.", ["§8.3", "§7.4"],
                  signed(hint("hm", ALICE, ALICE, 5), "mallory"), reject("signer-mismatch")))
    out.append(dv("subject-not-signer-identity", "bob-phone (delegated by bob) publishes a hint whose subject is alice.", ["§8.3"],
                  signed(hint("hb", ALICE, F.did("bob"), 1), "bob-phone"), reject("hint-subject-mismatch")))
    out.append(dv("expired-record", "Record past expiration is invalid.", ["§8.3"],
                  signed(hint("hx", ALICE, ALICE, 1, at=NOW - 200, ttl=100), "alice"), reject("expired")))
    h2 = signed(hint("h2", ALICE, ALICE, 2, at=NOW - 30), "alice")
    out.append(dv("seq-newer-wins", "Input seq 2 vs existing seq 1: newer sequence wins.", ["§8.3"],
                  h2, accept(type="reachability-hint", signer=ALICE, identity=ALICE, winner="input", conflict="newer-seq"), existing=h1))
    out.append(dv("seq-older-loses", "Input seq 1 vs existing seq 2: existing record kept.", ["§8.3"],
                  h1, accept(type="reachability-hint", signer=ALICE, identity=ALICE, winner="existing", conflict="older-seq"), existing=h2))
    h1b = signed(hint("h1b", ALICE, ALICE, 1, uri="wss://other.example.com/dsip"), "alice")
    out.append(dv("same-seq-live-conflict", "Two live records, same key, same seq, different content → warn; existing kept.", ["§8.3"],
                  h1b, accept(type="reachability-hint", signer=ALICE, identity=ALICE, winner="existing", conflict="same-seq-live"), existing=h1))
    out.append(dv("same-record-duplicate", "Identical record re-observed: no conflict.", ["§8.3"],
                  h1, accept(type="reachability-hint", signer=ALICE, identity=ALICE, winner="existing", conflict="none"), existing=h1))
    stale_existing = signed(hint("hs", ALICE, ALICE, 9, at=NOW - 7200, ttl=3600), "alice")
    out.append(dv("existing-expired-ignored", "An expired existing record carries no authority; the live input wins regardless of seq.",
                  ["§8.3"], h1, accept(type="reachability-hint", signer=ALICE, identity=ALICE, winner="input", conflict="none"),
                  existing=stale_existing))
    out.append(dv("schema-missing-seq", "Hint without seq fails the hint schema.", ["§8.3"],
                  signed({k: v for k, v in hint("hq", ALICE, ALICE, 1).items() if k != "seq"}, "alice"), reject("schema-invalid")))
    return out
