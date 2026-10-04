"""`did-webvh/` vectors — resolving a did:webvh v1.0 log for DSIP (v0.9 §7.2; spec-gap 101).

Every negative breaks exactly one rule of a log the builder made valid, so the expected reason is the rule
broken. Expected outcomes are authored from the spec: a valid log resolves to its last entry's `state`.
"""
from __future__ import annotations

import copy
import json
from datetime import datetime, timezone

from ..webvh import LogBuilder, kp, key_hash, mh_b58, multikey, sign_proof, jcs
from .common import vector

REFS = ["§7.2", "§8.1", "§8.4"]
NOW = int(datetime(2026, 6, 1, tzinfo=timezone.utc).timestamp())
K1, K2, K3, KX = kp("k1"), kp("k2"), kp("k3"), kp("intruder")
W1, W2, W3 = kp("w1"), kp("w2"), kp("w3")


def wid(k) -> str:
    return "did:key:" + multikey(k.public)


def wv(vid, desc, b: LogBuilder | None, expect, did=None, log=None, witness=None, cache=None, now=NOW, refs=None):
    inp = {"did": did if did is not None else b.did, "log": log if log is not None else b.text(),
           "witness": witness, "cache": cache, "now": now}
    return vector(f"did-webvh/{vid}", "did-webvh", desc, refs or REFS, {}, inp, expect)


def resolved(b: LogBuilder, ttl=3600):
    last = b.entries[-1]
    return {"outcome": "resolved", "versionId": last["versionId"], "versionTime": last["versionTime"],
            "document": last["state"], "ttl": ttl, "cache": last["versionId"]}


def rejected(reason):
    return {"outcome": "rejected", "reason": reason}


def three() -> LogBuilder:
    b = LogBuilder().create(K1)
    b.update(K1, doc_extra={"service": [{"id": "#sig", "type": "DSIPSignaling", "serviceEndpoint": "wss://relay.example/dsip"}]})
    return b.update(K1, doc_extra={"alsoKnownAs": ["https://example.com/alice"]})


def vectors() -> list[dict]:
    out = []

    # --- valid logs ------------------------------------------------------------------------------
    b = LogBuilder().create(K1)
    out.append(wv("create-resolves", "A one-entry log (create) resolves to its document.", b, resolved(b)))
    b = three()
    out.append(wv("updates-resolve-to-the-latest", "Three entries signed by the same update key resolve to the last entry's document.",
                  b, resolved(b)))
    b = LogBuilder().create(K1).update(K1, {"updateKeys": [multikey(K2.public)]}).update(K2, doc_extra={"alsoKnownAs": ["x:rotated"]})
    out.append(wv("rotation-takes-effect-next-entry", "Without pre-rotation, keys set in entry 2 (signed by the old key) sign from entry 3.",
                  b, resolved(b)))
    b = LogBuilder().create(K1, {"nextKeyHashes": [key_hash(K2)]})
    b.update(K2, {"updateKeys": [multikey(K2.public)], "nextKeyHashes": [key_hash(K3)]})
    out.append(wv("pre-rotation-resolves", "Under pre-rotation an entry is signed by its own committed keys.", b, resolved(b)))
    b = LogBuilder().create(K1, {"ttl": 600})
    out.append(wv("ttl-reported", "The ttl parameter is reported for DSIP's cache tier (§8.1).", b, resolved(b, ttl=600)))
    dsip_doc = {"service": [{"id": "#dsip", "type": "DSIPSignaling", "serviceEndpoint": "wss://relay.example/dsip"},
                            {"id": "#mbx", "type": "DSIPMailbox", "serviceEndpoint": {"did": "did:key:z6MkMailbox", "uri": "wss://mbx.example/dsip"}}],
                "keyAgreement": [{"id": "#ka", "type": "Multikey", "publicKeyMultibase": "z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc"}],
                "dsipDelegationRevocations": []}
    b = LogBuilder().create(K1, doc_extra=dsip_doc)
    out.append(wv("carries-dsip-document-properties", "The document DSIP reads — DSIPSignaling, DSIPMailbox, keyAgreement, dsipDelegationRevocations "
                  "(§7.2) — is returned unchanged.", b, resolved(b)))
    b = LogBuilder(path=("users", "alice")).create(K1)
    out.append(wv("path-did", "A DID with path segments (did:webvh:<scid>:example.com:users:alice).", b, resolved(b)))
    b = LogBuilder(domain="example.com%3A8443").create(K1)
    out.append(wv("port-did", "A DID with a port, percent-encoded as %3A.", b, resolved(b)))
    b = LogBuilder().create(K1, {"witness": {"threshold": 2, "witnesses": [{"id": wid(W1)}, {"id": wid(W2)}, {"id": wid(W3)}]}})
    v1 = b.entries[0]["versionId"]
    out.append(wv("witness-threshold-met", "Two of three witnesses approve the entry: threshold 2 met.", b, resolved(b),
                  witness=b.witness_file([(v1, W1), (v1, W3)])))
    b.update(K1, doc_extra={"alsoKnownAs": ["x:2"]})
    v2 = b.entries[1]["versionId"]
    out.append(wv("witness-approval-covers-earlier-entries", "A witness proof for a later entry approves every earlier one too.",
                  b, resolved(b), witness=b.witness_file([(v2, W1), (v2, W2)])))
    b = LogBuilder().create(K1).update(K1, {"deactivated": True})
    out.append(wv("deactivated", "A deactivated DID resolves to no document (did:webvh §Deactivate): DSIP treats it as having no keys.",
                  b, {"outcome": "deactivated", "versionId": b.entries[-1]["versionId"], "cache": b.entries[-1]["versionId"]}))
    b = LogBuilder().create(K1, {"portable": True})
    old = b.did
    st = copy.deepcopy(b.entries[-1]["state"])
    new = old.replace(":example.com", ":example.org")
    st = json.loads(json.dumps(st).replace(old, new))
    st["alsoKnownAs"] = [old]
    b.update(K1, state=st)
    out.append(wv("portable-move", "A portable DID moves domain: the SCID stays and the new document lists the old DID in alsoKnownAs.",
                  b, resolved(b)))
    out.append(wv("portable-move-resolved-by-old-did", "Resolving the pre-move DID returns the current (moved) document.", b,
                  resolved(b), did=old))
    b = LogBuilder().create(K1)
    b.entries[0]["versionTime"] = "2026-06-01T00:04:00Z"
    did = _rescid_did(b)
    out.append(wv("versiontime-within-tolerance", "An entry 4 minutes ahead of the resolver's clock is within the 5-minute tolerance.",
                  None, resolved(b), did=did, log=b.text()))

    # --- DSIP cache: rollback and fork (spec-gap 101) ---------------------------------------------
    b = three()
    out.append(wv("cache-at-latest-resolves", "The cache holds the latest versionId: resolved, cache unchanged.", b, resolved(b),
                  cache={"versionId": b.entries[2]["versionId"]}, refs=REFS + ["§8.1"]))
    out.append(wv("cache-behind-advances", "The cache holds an earlier versionId of this log: resolved, and the cache advances.",
                  b, resolved(b), cache={"versionId": b.entries[0]["versionId"]}))
    short = LogBuilder().create(K1)
    short.entries = copy.deepcopy(b.entries[:2])
    out.append(wv("rollback", "The host serves an older but valid log (2 entries) than the resolver has verified (3): rejected.",
                  None, rejected("rollback"), did=b.did, log=short.text(), cache={"versionId": b.entries[2]["versionId"]}))
    other = LogBuilder().create(K1)
    other.entries = copy.deepcopy(b.entries[:1])
    other.minute = 1
    other.update(K1, doc_extra={"alsoKnownAs": ["x:fork"]}).update(K1, doc_extra={"alsoKnownAs": ["x:fork2"]})
    out.append(wv("fork", "The log has a different entry 2 than the one the resolver verified: rejected.", None, rejected("fork"),
                  did=b.did, log=other.text(), cache={"versionId": b.entries[1]["versionId"]}))

    # --- the requested DID -------------------------------------------------------------------------
    good = LogBuilder().create(K1)
    for vid, did, why in [
        ("did-not-webvh", good.did.replace("did:webvh:", "did:web:"), "Not a did:webvh DID."),
        ("did-scid-length", good.did.replace(good.scid, good.scid[:-1]), "SCID shorter than 46 characters."),
        ("did-single-label-domain", good.did.replace("example.com", "localhost"), "A domain needs at least two labels."),
        ("did-ip-domain", good.did.replace("example.com", "127.0.0.1"), "An IP address is not a domain."),
        ("did-port-zero", good.did.replace("example.com", "example.com%3A0"), "Port 0."),
        ("did-dot-dot-path", good.did + ":..", "A '..' path segment."),
        ("did-encoded-dot-dot-path", good.did + ":%2E%2E", "A percent-encoded '..' path segment."),
    ]:
        out.append(wv(vid, why, None, rejected("invalid-did"), did=did, log=good.text()))
    out.append(wv("did-not-in-log", "Same SCID, but no entry's state.id is the requested DID.", None, rejected("identity"),
                  did=good.did.replace("example.com", "example.net"), log=good.text()))

    # --- log structure -----------------------------------------------------------------------------
    out.append(wv("empty-log", "An empty log.", None, rejected("log-malformed"), did=good.did, log=""))
    out.append(wv("not-json", "A line that is not JSON.", None, rejected("log-malformed"), did=good.did, log=good.text() + "{not json\n"))
    b = LogBuilder().create(K1)
    b.entries[0]["extra"] = 1
    out.append(wv("unknown-entry-key", "An entry with a key beyond versionId, versionTime, parameters, state, proof.", b, rejected("log-malformed")))
    b = LogBuilder().create(K1)
    b.entries[0]["proof"] = []
    out.append(wv("no-proof", "An entry with an empty proof array.", b, rejected("log-malformed")))

    # --- versionId, entryHash, SCID ------------------------------------------------------------------
    b = three()
    b.entries[1]["versionId"] = "3-" + b.entries[1]["versionId"].split("-", 1)[1]
    out.append(wv("version-number-gap", "Entry 2 numbered 3.", b, rejected("version-number")))
    b = three()
    b.entries[1]["state"]["alsoKnownAs"] = ["x:tampered"]
    out.append(wv("entry-hash-tampered-state", "Entry 2's state edited after it was hashed and signed.", b, rejected("entry-hash")))
    b = LogBuilder().create(K1)
    b.entries[0]["state"]["alsoKnownAs"] = ["x:tampered"]
    out.append(wv("scid-tampered-genesis", "The first entry's state edited: the SCID no longer recomputes (checked before its entryHash).",
                  b, rejected("scid")))

    # --- versionTime -------------------------------------------------------------------------------
    b = three()
    b.entries[2]["versionTime"] = b.entries[1]["versionTime"]
    b.resign(2, K1)
    out.append(wv("versiontime-equal", "Entry 3's versionTime equals entry 2's: must be strictly greater.", b, rejected("version-time")))
    b = three()
    b.entries[2]["versionTime"] = b.entries[2]["versionTime"].replace("Z", "+01:00")
    b.resign(2, K1)
    out.append(wv("versiontime-not-utc", "A versionTime with a +01:00 offset.", b, rejected("version-time")))
    b = LogBuilder().create(K1)
    b.entries[0]["versionTime"] = "2026-06-01T00:06:00Z"
    did = _rescid_did(b)
    out.append(wv("versiontime-beyond-tolerance", "An entry 6 minutes ahead of the resolver's clock.", None, rejected("version-time"),
                  did=did, log=b.text()))

    # --- parameters --------------------------------------------------------------------------------
    b = three()
    b.entries[1]["parameters"]["colour"] = "blue"
    b.resign(1, K1)
    out.append(wv("unknown-parameter", "An unknown parameter.", b, rejected("parameters")))
    b = LogBuilder().create(K1, {"method": "did:webvh:9.9"})
    out.append(wv("method-unknown", "method did:webvh:9.9 in the first entry: not a version of the method.", b, rejected("parameters")))
    b = LogBuilder().create(K1, {"method": "did:webvh:0.5"})
    out.append(wv("method-older-version", "method did:webvh:0.5: an earlier version, which DSIP resolvers do not support "
                  "(v1.0 only, spec-gap 101; did:webvh §Parameters: reject values outside the supported versions).", b, rejected("parameters")))
    b = three()
    b.entries[1]["parameters"]["scid"] = b.scid
    b.resign(1, K1)
    out.append(wv("scid-after-first-entry", "scid repeated in entry 2.", b, rejected("parameters")))
    b = three()
    b.entries[1]["parameters"]["portable"] = True
    b.resign(1, K1)
    out.append(wv("portable-true-later", "portable: true after the first entry.", b, rejected("parameters")))
    b = LogBuilder().create(K1, {"witness": {"threshold": 0, "witnesses": [{"id": wid(W1)}]}})
    out.append(wv("witness-threshold-zero", "A witness threshold of 0.", b, rejected("parameters")))
    b = LogBuilder().create(K1, {"witness": {"threshold": 1, "witnesses": [{"id": wid(W1)}, {"id": wid(W1)}]}})
    out.append(wv("witness-duplicate-ids", "The same witness listed twice.", b, rejected("parameters")))
    b = LogBuilder().create(K1).update(K1, {"deactivated": True}).update(K1, doc_extra={"alsoKnownAs": ["x:late"]})
    out.append(wv("entry-after-deactivation", "An entry after the one that deactivated the DID.", b, rejected("after-deactivation")))

    # --- keys and proofs ---------------------------------------------------------------------------
    b = LogBuilder().create(K1).update(K2, {"updateKeys": [multikey(K2.public)]})
    out.append(wv("new-key-signs-its-own-entry", "Without pre-rotation, keys set in an entry do not sign that entry.", b,
                  rejected("unauthorized-key")))
    b = LogBuilder().create(K1).update(KX, doc_extra={"alsoKnownAs": ["x:intruder"]})
    out.append(wv("signed-by-unlisted-key", "Entry 2 signed by a key that was never an update key.", b, rejected("unauthorized-key")))
    b = LogBuilder().create(K1, {"nextKeyHashes": [key_hash(K2)]})
    b.update(K3, {"updateKeys": [multikey(K3.public)], "nextKeyHashes": []})
    out.append(wv("pre-rotation-uncommitted-key", "Under pre-rotation, a new update key whose hash was not committed.", b,
                  rejected("pre-rotation")))
    b = LogBuilder().create(K1, {"nextKeyHashes": [key_hash(K2)]})
    b.update(K2, {"updateKeys": [multikey(K2.public)]})
    out.append(wv("pre-rotation-omits-nexthashes", "Under pre-rotation, nextKeyHashes must be explicit in the next entry.", b,
                  rejected("pre-rotation")))
    b = three()
    pr = b.entries[2]["proof"][0]
    pr["proofValue"] = pr["proofValue"][:-3] + ("111" if not pr["proofValue"].endswith("111") else "222")
    out.append(wv("signature-invalid", "Entry 3's signature altered.", b, rejected("proof")))
    b = three()
    doc = {k: v for k, v in b.entries[2].items() if k != "proof"}
    p = sign_proof(doc, K1, b.entries[2]["versionTime"])
    p["cryptosuite"] = "eddsa-rdfc-2022"
    b.entries[2]["proof"] = [p]
    out.append(wv("wrong-cryptosuite", "A proof naming another cryptosuite.", b, rejected("proof")))
    b = three()
    mk1, mkx = multikey(K1.public), multikey(KX.public)
    b.entries[2]["proof"][0]["verificationMethod"] = f"did:key:{mkx}#{mk1}"
    out.append(wv("did-key-body-fragment-mismatch", "A verificationMethod whose did:key body differs from its fragment.", b, rejected("proof")))

    # --- identity ----------------------------------------------------------------------------------
    b = LogBuilder().create(K1)
    st = copy.deepcopy(b.entries[0]["state"])
    st = json.loads(json.dumps(st).replace(b.did, b.did.replace(":example.com", ":example.org")))
    b.update(K1, state=st)
    out.append(wv("move-not-portable", "The DID moves domain without portable: true.", b, rejected("identity"),
                  did=b.entries[0]["state"]["id"]))
    b = LogBuilder().create(K1, {"portable": True})
    st = json.loads(json.dumps(b.entries[0]["state"]).replace(b.did, b.did.replace(":example.com", ":example.org")))
    b.update(K1, state=st)
    out.append(wv("move-without-alsoknownas", "A portable move whose new document does not list the old DID in alsoKnownAs.", b,
                  rejected("identity"), did=b.entries[0]["state"]["id"]))

    # --- witnesses ---------------------------------------------------------------------------------
    b = LogBuilder().create(K1, {"witness": {"threshold": 2, "witnesses": [{"id": wid(W1)}, {"id": wid(W2)}]}})
    v1 = b.entries[0]["versionId"]
    out.append(wv("witness-threshold-not-met", "One of two required witnesses approved.", b, rejected("witness"),
                  witness=b.witness_file([(v1, W1)])))
    out.append(wv("witness-file-missing", "Witnesses are configured but no did-witness.json was supplied.", b, rejected("witness")))
    out.append(wv("witness-same-witness-twice", "The same witness approving twice counts once.", b, rejected("witness"),
                  witness=b.witness_file([(v1, W1), (v1, W1)])))
    foreign = LogBuilder(domain="other.example").create(K2)
    out.append(wv("witness-proof-for-another-log", "Approvals for a versionId that is not in this log are no evidence.", b,
                  rejected("witness"), witness=foreign.witness_file([(foreign.entries[0]["versionId"], W1),
                                                                     (foreign.entries[0]["versionId"], W2)])))

    # --- I-JSON (RFC 7493), which JCS assumes; found by probing the three implementations ----------
    b = LogBuilder().create(K1, doc_extra={"n": 2**53 - 1})
    out.append(wv("ijson-integer-at-max-safe", "An integer of exactly 2^53−1 in the document is allowed.", b, resolved(b)))
    b = LogBuilder().create(K1, doc_extra={"n": 2**53})
    out.append(wv("ijson-integer-beyond-max-safe", "An integer of 2^53 is outside I-JSON: implementations that read numbers as "
                  "doubles would hash a different value.", b, rejected("log-malformed")))
    b = LogBuilder().create(K1)
    t = b.text().replace('{"versionId"', '{"versionTime":"2026-01-01T00:01:00Z","versionId"', 1)
    out.append(wv("ijson-duplicate-name", "An entry with a member name twice: parsers differ on which one wins.", None,
                  rejected("log-malformed"), did=b.did, log=t))
    b = LogBuilder().create(K1)
    t = b.text().replace('"authentication"', '"x":"\\ud800","authentication"', 1)
    out.append(wv("ijson-lone-surrogate", "A string holding an escaped lone surrogate.", None, rejected("log-malformed"),
                  did=b.did, log=t))
    b = LogBuilder().create(K1, {"witness": {"threshold": 1, "witnesses": [{"id": wid(W1)}]}})
    v1 = b.entries[0]["versionId"]
    wt = b.witness_file([(v1, W1)])
    out.append(wv("witness-file-not-ijson", "A witness file with a duplicate member name counts as absent.", b, rejected("witness"),
                  witness=wt.replace('[{"versionId"', '[{"versionId":"x","versionId"', 1)))
    out.append(wv("did-path-not-utf8", "A path segment whose percent-decoded bytes are not UTF-8 (%FF).", None,
                  rejected("invalid-did"), did=good.did + ":%FF", log=good.text()))
    out.append(wv("did-path-leading-nbsp", "A path segment beginning with U+00A0 (Unicode White_Space).", None,
                  rejected("invalid-did"), did=good.did + ":%C2%A0x", log=good.text()))
    b = LogBuilder().create(K1, doc_extra={"n": 0})
    out.append(wv("ijson-minus-zero", "`-0` in the document is an integer; JCS writes it `0`, so the hash holds.", None, resolved(b),
                  did=b.did, log=b.text().replace('"n":0', '"n":-0', 1)))
    b = LogBuilder().create(K1)
    out.append(wv("cache-malformed-is-absent", "A cache value that is not <n>-<hash> is treated as absent.", b, resolved(b),
                  cache={"versionId": "abc"}))

    # --- check order -------------------------------------------------------------------------------
    b = three()
    b.entries[2]["versionTime"] = b.entries[1]["versionTime"]
    b.entries[2]["state"]["alsoKnownAs"] = ["x:also-tampered"]
    out.append(wv("first-failing-check-wins", "Entry 3 has both a non-increasing versionTime and a broken hash: versionTime is "
                  "checked first (README check order).", b, rejected("version-time")))
    return out


def _rescid_did(b: LogBuilder) -> str:
    """After `resign(0, …)` of an edited first entry the SCID is stale; rebuild the entry so it is valid again."""
    e = b.entries[0]
    pre = {k: v for k, v in e.items() if k != "proof"}
    old = e["parameters"]["scid"]
    pre = json.loads(json.dumps(pre).replace(old, "{SCID}"))
    pre["versionId"] = "{SCID}"
    scid = mh_b58(jcs(pre))
    e2 = json.loads(json.dumps(pre).replace("{SCID}", scid))
    h = dict(e2)
    h["versionId"] = scid
    e2["versionId"] = "1-" + mh_b58(jcs(h))
    from ..webvh import sign_proof as sp
    e2["proof"] = [sp(e2, K1, e2["versionTime"])]
    b.entries[0] = e2
    return e2["state"]["id"]
