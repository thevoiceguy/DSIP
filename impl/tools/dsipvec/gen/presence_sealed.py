"""Sealed presence vectors (`presence/0.2`, P§12; v0.17 draft, spec-gaps 152–157).

Keys, tags and ciphertexts are computed here with the `cryptography` library's own HKDF and AES-GCM from the
construction P§12 writes down, and HPKE with the generator's RFC 9180 code; the verdicts (which record opens, which
is unreadable and why, which subscription is given what) are written from the draft, not from an implementation.
"""
from __future__ import annotations

import base64
import hashlib
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .. import fixtures as F
from ..messaging import hpke_seal, x25519_public
from .common import NOW, base, signed, default_context, vector, accept, reject, uid

APH, BPH, BLA, CPH = F.did("alice-phone"), F.did("bob-phone"), F.did("bob-laptop"), F.did("carol-phone")
ALICE, BOB, CAROL = F.did("alice"), F.did("bob"), F.did("carol")
AUTH = "did:key:z6MkAuthorityRelay11111111111111111111111111"
P02 = "presence/0.2"


def did_key_secret(name: str) -> bytes:
    """The X25519 key agreement secret `did:key` derives from a fixture identity's Ed25519 seed (M§6.9), unclamped."""
    return hashlib.sha512(hashlib.sha256(f"dsip-vector:{name}".encode()).digest()).digest()[:32]


def clamped(sk: bytes) -> bytes:
    b = bytearray(sk)
    b[0] &= 248
    b[31] = (b[31] & 127) | 64
    return bytes(b)


def _hkdf(secret: bytes, info: bytes, n: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=n, salt=None, info=info).derive(clamped(secret))


def tag(secret: bytes, subject: str, label: str) -> str:
    raw = _hkdf(secret, b"dsip presence audience v1\0" + subject.encode() + b"\0" + label.encode(), 10)
    return "k-" + base64.b32encode(raw).decode().rstrip("=").lower()


def key(secret: bytes, subject: str, kid: str) -> bytes:
    return _hkdf(secret, b"dsip presence key v1\0" + subject.encode() + b"\0" + kid.encode(), 32)


def b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def aad(r: dict) -> bytes:
    return (b"dsip presence v1\0" + r["subject"].encode() + b"\0" + r["device"].encode() + b"\0"
            + r.get("audience", "").encode() + b"\0" + r["kid"].encode() + b"\0"
            + r["seq"].to_bytes(8, "big") + r["expires_at"].to_bytes(8, "big"))


def nonce(label: str) -> bytes:
    return hashlib.sha256(f"presence-nonce:{label}".encode()).digest()[:12]


def seal(r: dict, k: bytes, label: str, plaintext: bytes | None = None, state: str = "busy") -> str:
    """sealed_state for record `r` (its fields as they will be sent) under key `k`."""
    pt = plaintext if plaintext is not None else (json.dumps({"state": state}, separators=(",", ":")).encode().ljust(128, b" "))
    n = nonce(label)
    return b64(n + AESGCM(k).encrypt(n, pt, aad(r)))


BOB_S, ALICE_S, CAROL_S = did_key_secret("bob"), did_key_secret("alice"), did_key_secret("carol")
FAMILY = tag(BOB_S, BOB, "family")
WORK = tag(BOB_S, BOB, "work")
K = {kid: key(BOB_S, BOB, kid) for kid in ("main.0", "main.1", f"{FAMILY}.0", f"{FAMILY}.3")}


def sealed_fields(label, device=BPH, seq=1, at=NOW, ttl=300, audience=None, kid="main.0", state="busy", k=None,
                  plaintext=None, subject=BOB):
    """The fields of a sealed record (P§12.2) as a device publishes it, sealed under Bob's key for `kid`."""
    r = {"subject": subject, "device": device, "kid": kid, "seq": seq, "expires_at": at + ttl}
    if audience is not None:
        r["audience"] = audience
    r["sealed_state"] = seal(r, k if k is not None else key(BOB_S, subject, kid), label, plaintext, state)
    return r


# ---------------------------------------------------------------- presence kind: keys, sealing, opening (P§12)

def presence_vectors() -> list[dict]:
    def pv(vid, desc, refs, inp, expect, now=NOW):
        return vector(f"presence/{vid}", "presence", desc, refs, {"now": now}, inp, expect)

    hexkeys = lambda *kids: {kid: K[kid].hex() for kid in kids}
    out = [
        pv("audience-tag", "An audience Bob labels family is written on the wire as k- and the base32 of 10 bytes of "
           "HKDF from his key agreement secret (P§12.1): the label never leaves his devices.", ["P§12.1"],
           {"check": "audience-tag", "secret_hex": BOB_S.hex(), "subject": BOB, "label": "family"}, {"tag": FAMILY}),
        pv("audience-tag-per-label", "Another label gives another tag.", ["P§12.1"],
           {"check": "audience-tag", "secret_hex": BOB_S.hex(), "subject": BOB, "label": "work"}, {"tag": WORK}),
        pv("audience-tag-from-clamped-secret", "The secret is used clamped (RFC 7748), so the clamped and unclamped "
           "encodings of one key give the same tag (P§12.1).", ["P§12.1"],
           {"check": "audience-tag", "secret_hex": clamped(BOB_S).hex(), "subject": BOB, "label": "family"}, {"tag": FAMILY}),
        pv("audience-tag-per-subject", "The subject is part of the derivation: the same secret and label under another "
           "subject name give another tag.", ["P§12.1"],
           {"check": "audience-tag", "secret_hex": BOB_S.hex(), "subject": F.BOB_WEB, "label": "family"},
           {"tag": tag(BOB_S, F.BOB_WEB, "family")}),
        pv("key-main", "The key of main.0, the first epoch of records with no audience (P§12.1).", ["P§12.1"],
           {"check": "key", "secret_hex": BOB_S.hex(), "subject": BOB, "kid": "main.0"}, {"key_hex": K["main.0"].hex()}),
        pv("key-audience-epoch", "The key of the family audience at epoch 3: the kid is the tag, a dot and the epoch.",
           ["P§12.1"], {"check": "key", "secret_hex": BOB_S.hex(), "subject": BOB, "kid": f"{FAMILY}.3"},
           {"key_hex": K[f"{FAMILY}.3"].hex()}),
    ]
    r = sealed_fields("seal-busy")
    out.append(pv("seal-record", "A busy record under main.0 with a given nonce: the nonce, then AES-256-GCM of "
                  "{\"state\": \"busy\"} padded with spaces to 128 bytes, AAD binding subject, device, audience, kid, seq and "
                  "expires_at (P§12.2).", ["P§12.2"],
                  {"check": "seal-record", "record": {k: v for k, v in r.items() if k != "sealed_state"}, "state": "busy",
                   "key_hex": K["main.0"].hex(), "nonce_hex": nonce("seal-busy").hex()}, {"sealed_state": r["sealed_state"]}))

    def ov(vid, desc, rec, keys, expect, refs=("P§12.4",)):
        return pv(vid, desc, list(refs), {"check": "open-record", "record": rec, "keys": keys}, expect)

    fam = sealed_fields("open-fam", audience=FAMILY, kid=f"{FAMILY}.3", state="dnd")
    pad = lambda s: s.encode().ljust(128, b" ")
    out += [
        ov("open-record", "A record sealed under main.0 opens with that key: busy.", r, hexkeys("main.0"),
           accept(state="busy")),
        ov("open-record-audience", "A family record at epoch 3 opens with the family key of epoch 3.", fam,
           hexkeys(f"{FAMILY}.3"), accept(state="dnd")),
        ov("open-record-unknown-state", "A sealed state outside the registry opens and is returned raw; P§5's fallback is "
           "the combining rule's.", sealed_fields("open-unk", state="in-transit"), hexkeys("main.0"),
           accept(state="in-transit")),
        ov("open-record-previous-epoch", "A subscriber holding main.0 and main.1 still reads a record under main.0 "
           "(P§12.4: two epochs are kept).", r, hexkeys("main.0", "main.1"), accept(state="busy")),
        ov("open-record-key-unknown", "A record under main.1 when the subscriber holds only main.0 is unreadable: "
           "presence-key-unknown.", sealed_fields("open-e1", kid="main.1"), hexkeys("main.0"), reject("presence-key-unknown")),
        ov("open-record-wrong-key", "A key held under the record's kid that is not the key it was sealed with does not "
           "open it.", r, {"main.0": K["main.1"].hex()}, reject("aead-open-failed")),
        ov("open-record-truncated", "A sealed_state shorter than 156 bytes is unreadable before any decryption.",
           {**r, "sealed_state": r["sealed_state"][:-4]}, hexkeys("main.0"), reject("sealed-too-short")),
        ov("open-record-spliced-seq", "The same ciphertext with seq raised: the AAD differs, so it does not open (P§12.2).",
           {**r, "seq": 2}, hexkeys("main.0"), reject("aead-open-failed")),
        ov("open-record-spliced-expiry", "The same ciphertext with a later expires_at does not open.",
           {**r, "expires_at": r["expires_at"] + 60}, hexkeys("main.0"), reject("aead-open-failed")),
        ov("open-record-spliced-device", "The same ciphertext under another device of Bob's does not open: one device's "
           "word cannot be shown as another's.", {**r, "device": BLA}, hexkeys("main.0"), reject("aead-open-failed")),
        ov("open-record-spliced-audience", "A family ciphertext with its audience changed to work, its kid kept, does not "
           "open: the audience is in the AAD.", {**fam, "audience": WORK}, hexkeys(f"{FAMILY}.3"),
           reject("aead-open-failed")),
        ov("open-record-spliced-subject", "The same ciphertext under another subject does not open.",
           {**r, "subject": CAROL}, hexkeys("main.0"), reject("aead-open-failed")),
        ov("open-record-plaintext-extra-key", "A plaintext with a key besides state is unreadable.",
           sealed_fields("open-x", plaintext=pad('{"state": "busy", "note": "x"}')), hexkeys("main.0"),
           reject("presence-plaintext-invalid")),
        ov("open-record-plaintext-bad-token", "A sealed state that is not a P§5 token is unreadable.",
           sealed_fields("open-t", plaintext=pad('{"state": "Busy"}')), hexkeys("main.0"), reject("presence-plaintext-invalid")),
        ov("open-record-plaintext-not-json", "A plaintext that is not JSON is unreadable.",
           sealed_fields("open-j", plaintext=pad("busy")), hexkeys("main.0"), reject("presence-plaintext-invalid")),
        ov("open-record-plaintext-state-not-string", "A state that is not a string is unreadable.",
           sealed_fields("open-n", plaintext=pad('{"state": 3}')), hexkeys("main.0"), reject("presence-plaintext-invalid")),
        ov("open-record-plaintext-not-utf8", "A plaintext that is not UTF-8 is unreadable.",
           sealed_fields("open-u", plaintext=b'{"state": "\xff"}'.ljust(128, b" ")), hexkeys("main.0"),
           reject("presence-plaintext-invalid")),
    ]
    out += grant_keys_vectors(pv) + view_vectors(pv)
    return out


def grant_with_keys(label, keys, to=ALICE, audience=None, alg="hpke-base-x25519-sha256-aes128gcm", recipient=None,
                    plaintext=None, aad_from=None):
    """A grant from Bob's phone to `to` carrying `keys` ({kid: key}) sealed to `recipient` (default: `to`'s secret)."""
    g = base("grant", label, BPH, NOW, to=to, session=uid(f"{label}-intro", NOW - 60), scope=["dsip.subscribe"],
             valid_until=NOW + 86400)
    if audience is not None:
        g["presence_audience"] = audience
    pt = plaintext if plaintext is not None else json.dumps(
        {"keys": [{"kid": kid, "key": b64(k)} for kid, k in keys.items()]}).encode()
    pt = pt.ljust(-(-len(pt) // 256) * 256, b" ") if plaintext is None else pt
    src = aad_from or g
    a = src["id"].encode() + b"\0" + src["from"].encode() + b"\0" + src["to"].encode()
    sk_e = hashlib.sha256(f"presence-hpke:{label}".encode()).digest()
    pk_r = x25519_public(clamped(recipient or ALICE_S))
    enc, ct = hpke_seal(pk_r, b"dsip presence keys v1", a, pt, sk_e)
    g["presence_keys"] = {"alg": alg, "enc": b64(enc), "ct": b64(ct)}
    return g


def grant_keys_vectors(pv) -> list[dict]:
    def gv(vid, desc, g, expect, secret=ALICE_S):
        return pv(vid, desc, ["P§12.3", "§19.4"],
                  {"check": "grant-keys-open", "grant": g, "recipient_secret_hex": secret.hex()}, expect)

    two = {"main.0": K["main.0"], f"{FAMILY}.3": K[f"{FAMILY}.3"]}
    ok = grant_with_keys("gk-ok", two, audience=FAMILY)
    out_keys = {kid: k.hex() for kid, k in two.items()}
    pad = lambda b: b.ljust(256, b" ")
    entries = lambda *e: json.dumps({"keys": list(e)}).encode()
    return [
        gv("grant-keys-open", "A family grant carries main.0 and the family key of epoch 3, sealed to Alice's identity: "
           "any of her devices opens them (P§12.3).", ok, accept(keys=out_keys)),
        gv("grant-keys-main-only", "A grant with no presence_audience carries the main key alone.",
           grant_with_keys("gk-main", {"main.0": K["main.0"]}), accept(keys={"main.0": K["main.0"].hex()})),
        gv("grant-keys-wrong-recipient", "Carol cannot open keys sealed to Alice.", ok, reject("sealed-open-failed"),
           secret=CAROL_S),
        gv("grant-keys-spliced-to-other-grant", "Keys sealed for one grant, carried by another (another id): the AAD "
           "differs, so they do not open.", {**ok, "id": uid("gk-other", NOW)}, reject("sealed-open-failed")),
        gv("grant-keys-spliced-to-other-grantee", "Keys sealed to Alice under a grant naming Alice, carried by a grant "
           "naming Carol, sealed to Carol: the AAD names Alice, so Carol's open fails.",
           grant_with_keys("gk-to", two, to=CAROL, audience=FAMILY, recipient=CAROL_S,
                           aad_from={**ok, "id": uid("gk-to", NOW)}), reject("sealed-open-failed"), secret=CAROL_S),
        gv("grant-keys-unsupported-alg", "An unknown alg is not opened.",
           grant_with_keys("gk-alg", two, audience=FAMILY, alg="hpke-base-p256-sha256-aes128gcm"),
           reject("sealed-alg-unsupported")),
        gv("grant-keys-foreign-scope", "A grant with no presence_audience carrying the family key: a grant carries no "
           "scope but main and its own audience (P§12.3).", grant_with_keys("gk-foreign", two), reject("sealed-plaintext-invalid")),
        gv("grant-keys-not-padded", "A plaintext that is not a multiple of 256 bytes is refused.",
           grant_with_keys("gk-pad", {}, plaintext=entries({"kid": "main.0", "key": b64(K["main.0"])})),
           reject("sealed-plaintext-invalid")),
        gv("grant-keys-short-key", "A key that is not 32 bytes is refused.",
           grant_with_keys("gk-short", {}, plaintext=pad(entries({"kid": "main.0", "key": b64(K["main.0"][:31])}))),
           reject("sealed-plaintext-invalid")),
        gv("grant-keys-bad-kid", "A kid with a leading zero in its epoch is not a kid.",
           grant_with_keys("gk-kid", {}, plaintext=pad(entries({"kid": "main.01", "key": b64(K["main.0"])}))),
           reject("sealed-plaintext-invalid")),
        gv("grant-keys-extra-field", "An entry with a field besides kid and key is refused.",
           grant_with_keys("gk-extra", {}, plaintext=pad(entries({"kid": "main.0", "key": b64(K["main.0"]), "x": 1}))),
           reject("sealed-plaintext-invalid")),
        gv("grant-keys-not-keys", "A plaintext that is not {\"keys\": [...]} is refused.",
           grant_with_keys("gk-nk", {}, plaintext=pad(b'{"key": []}')), reject("sealed-plaintext-invalid")),
        gv("grant-keys-empty-list", "An empty key list opens: nothing to read yet.",
           grant_with_keys("gk-empty", {}), accept(keys={})),
    ]


def view_vectors(pv) -> list[dict]:
    def vv(vid, desc, records, keys, asserted, expect):
        inp = {"check": "view", "records": records, "keys": {kid: K[kid].hex() for kid in keys}}
        if asserted is not None:
            inp["asserted"] = asserted
        return pv(vid, desc, ["P§12.4", "P§4"], inp, expect)

    plain = lambda state, device, exp=NOW + 100: {"subject": BOB, "device": device, "state": state, "seq": 1, "expires_at": exp}
    res = lambda state, source, unreadable=(), token=None: {"state": state, "token": token or state, "source": source,
                                                              "unreadable": list(unreadable)}
    s_dnd = sealed_fields("v-dnd", device=BLA, state="dnd")
    s_new = sealed_fields("v-new", device=BLA, kid="main.1", state="dnd")
    return [
        vv("view-sealed-and-plain", "A plain away record and a sealed dnd record the subscriber can open: dnd.",
           [plain("away", BPH), s_dnd], ["main.0"], "offline", res("dnd", "record")),
        vv("view-unreadable-takes-no-part", "The sealed dnd record under a key the subscriber lacks takes no part: the "
           "plain away record stands, and the laptop is listed unreadable (P§12.4, D4).",
           [plain("away", BPH), s_new], ["main.0"], "offline", res("away", "record", [BLA])),
        vv("view-unreadable-not-offline", "Only an unreadable record and an offline assertion: offline from nothing, "
           "never a guess at the sealed state.", [s_new], ["main.0"], "offline", res("offline", "none", [BLA])),
        vv("view-unreadable-and-assertion", "Only an unreadable record and an available assertion (another device of "
           "Bob's is bound with no record): available from the assertion.", [s_new], [], "available",
           res("available", "assertion", [BLA])),
        vv("view-sealed-expired", "A sealed record past its expires_at opens but is not valid: offline.",
           [sealed_fields("v-exp", ttl=60, at=NOW - 100)], ["main.0"], "offline", res("offline", "none")),
        vv("view-sealed-unknown-state", "An opened unknown state ranks and shows as available, its token kept (P§5).",
           [sealed_fields("v-unk", state="in-transit")], ["main.0"], None, res("available", "record", token="in-transit")),
    ]


# ---------------------------------------------------------------- payload, semantic, envelope (P§12.2, P§12.3)

V02 = {**F.VERSION, "profiles": [P02]}
SUPPORTED_02 = {**F.SUPPORTED, "profiles": [*F.SUPPORTED["profiles"], "presence/0.1", P02]}


def sealed_record(label, audience=None, kid="main.0", version=None, device=BPH, frm=None, at=NOW, **kw):
    """A whole sealed record payload from Bob's phone to its authority."""
    f = sealed_fields(label, device=device, audience=audience, kid=kid, at=at, **kw)
    return base("presence", label, frm or device, at, 300, to=F.RELAY_WEB, version=version or V02, **f)


def payload_vectors() -> list[dict]:
    def pv(vid, desc, refs, schema, payload, ok=True):
        return vector(f"payload/{vid}", "payload", desc, refs, {}, {"schema": schema, "payload": payload},
                      accept() if ok else reject("schema-invalid"))

    r = sealed_record("pps", audience=FAMILY, kid=f"{FAMILY}.3")
    drop = lambda m, k: {key: v for key, v in m.items() if key != k}
    g = grant_with_keys("pgk", {"main.0": K["main.0"]})
    return [
        pv("presence-sealed-valid", "A sealed record: kid and sealed_state in place of state (P§12.2).", ["P§12.2"],
           "presence", r),
        pv("presence-sealed-and-state-invalid", "state and sealed_state never both appear (P§12.2).", ["P§12.2"],
           "presence", {**r, "state": "busy"}, ok=False),
        pv("presence-sealed-without-kid-invalid", "A sealed record names its key.", ["P§12.2"], "presence",
           drop(r, "kid"), ok=False),
        pv("presence-kid-without-sealed-invalid", "kid appears only with sealed_state: a plain record with a kid is "
           "invalid.", ["P§12.2"], "presence", {**drop(r, "sealed_state"), "state": "busy"}, ok=False),
        pv("presence-neither-state-nor-sealed-invalid", "A record carries its state, plain or sealed.", ["P§12.2"],
           "presence", drop(r, "sealed_state"), ok=False),
        pv("presence-kid-epoch-leading-zero-invalid", "An epoch is written without leading zeros (P§12.1).", ["P§12.1"],
           "presence", {**r, "kid": f"{FAMILY}.03"}, ok=False),
        pv("presence-kid-without-epoch-invalid", "A kid is a scope, a dot and an epoch (P§12.1).", ["P§12.1"],
           "presence", {**r, "kid": FAMILY}, ok=False),
        pv("presence-sealed-state-not-base64url-invalid", "sealed_state is unpadded base64url (P§12.2).", ["P§12.2"],
           "presence", {**r, "sealed_state": r["sealed_state"] + "="}, ok=False),
        pv("grant-presence-keys-valid", "A grant may carry presence_keys, {alg, enc, ct} (P§12.3, §19.4).",
           ["P§12.3", "§19.4"], "grant", g),
        pv("grant-presence-keys-missing-enc-invalid", "presence_keys carries alg, enc and ct.", ["P§12.3"], "grant",
           {**g, "presence_keys": drop(g["presence_keys"], "enc")}, ok=False),
        pv("grant-presence-keys-extra-field-invalid", "presence_keys takes no other field.", ["P§12.3"], "grant",
           {**g, "presence_keys": {**g["presence_keys"], "kid": "main.0"}}, ok=False),
    ]


def semantic_vectors() -> list[dict]:
    def sv(vid, desc, refs, payload, expect):
        return vector(f"semantic/{vid}", "semantic", desc, refs, {"now": NOW, "supported": SUPPORTED_02},
                      {"payload": payload}, expect)

    bad = reject("presence-sealed-invalid", "presence.sealed-invalid")
    err = base("error", "pserr", F.RELAY_WEB, NOW + 1, to=BPH, in_reply_to=uid("pse", NOW), reason="presence.sealed-invalid")
    return [
        sv("presence-sealed-accepted", "A sealed record naming presence/0.2 whose kid is for its audience passes; the "
           "pipeline reports no state, which it cannot read (P§12.2).", ["P§12.2"],
           sealed_record("pse", audience=FAMILY, kid=f"{FAMILY}.3"), accept()),
        sv("presence-sealed-main-accepted", "A sealed record with no audience under main passes.", ["P§12.2"],
           sealed_record("psm"), accept()),
        sv("presence-sealed-without-profile", "A sealed record that names only presence/0.1 is refused (P§12.2, P§12.6).",
           ["P§12.2", "P§12.6"], sealed_record("psp", version={**F.VERSION, "profiles": ["presence/0.1"]}), bad),
        sv("presence-sealed-kid-main-with-audience", "A family record sealed under a main key: its kid is not for its "
           "audience.", ["P§12.2"], sealed_record("psk", audience=FAMILY, kid="main.0"), bad),
        sv("presence-sealed-kid-of-other-audience", "A family record under the work audience's key is refused.",
           ["P§12.2"], sealed_record("psw", audience=FAMILY, kid=f"{WORK}.0"), bad),
        sv("presence-sealed-audience-kid-without-audience", "A record with no audience under an audience's key is "
           "refused: it would be routed to every subscriber.", ["P§12.2"], sealed_record("psa", kid=f"{FAMILY}.0"), bad),
        sv("presence-sealed-audience-main", "A sealed record's audience is never main, which would share a kid with "
           "the records of no audience.", ["P§12.2"], sealed_record("psn", audience="main", kid="main.0"), bad),
        sv("presence-sealed-signer-mismatch-first", "A sealed record whose device is not its signer fails the signer "
           "check first (P§3 before P§12.2).", ["P§3", "P§12.2"],
           sealed_record("pss", device=BLA, frm=BPH, version={**F.VERSION, "profiles": ["presence/0.1"]}),
           reject("presence-signer-mismatch", "presence.signer-mismatch")),
        sv("reason-presence-sealed-invalid-registered", "presence.sealed-invalid is registered for error (P§9).",
           ["§15.4", "P§9"], err, accept(effective={"reason": "presence.sealed-invalid", "fallback": "none"})),
    ]


def envelope_vectors() -> list[dict]:
    ctx = default_context(supported=SUPPORTED_02)
    return [
        vector("envelope/presence-sealed-accepted", "envelope", "A signed sealed record from Bob's phone passes the "
               "pipeline: the signature covers kid and sealed_state, and no state is reported (P§12.2).",
               ["P§12.2", "§10.2"], ctx, {"envelope": signed(sealed_record("eps"), "bob-phone")},
               accept(type="presence", signer=BPH, identity=BPH)),
    ]


# ---------------------------------------------------------------- state: the authority (P§12.6)

def state_vectors() -> list[dict]:
    from .state import IDENTITIES

    def step(event, emit, **snaps):
        return {"event": event, "expect": {"emit": emit, **snaps}}

    def trace(vid, desc, refs, steps):
        return vector(f"state/{vid}", "state", desc, refs, {"component": "authority", "start": NOW, "identities": IDENTITIES},
                      {"steps": steps}, {})

    def rec(label, device=BPH, seq=1, at=NOW, audience=None, kid="main.0", state=None):
        m = {"type": "presence", "id": uid(label, at), "from": device, "to": AUTH, "subject": BOB, "device": device,
             "seq": seq, "issued_at": at, "expires_at": at + 300}
        if state is not None:  # a plain record
            m["state"] = state
            if audience is not None:
                m["audience"] = audience
            return m
        m.update(sealed_fields(label, device=device, seq=seq, at=at, audience=audience, kid=kid))
        return m

    def summary(r):
        return {"id": r["id"], "device": r["device"], "seq": r["seq"], "expires_at": r["expires_at"],
                **{k: r[k] for k in ("state", "kid", "sealed_state", "audience") if k in r}}

    def body(asserted, *recs):
        b = {"event": "presence", "state": asserted}
        if recs:
            b["records"] = [summary(r) for r in sorted(recs, key=lambda r: (r["device"], r.get("audience", "")))]
        return b

    def grant(label, to, audience=None):
        g = {"id": uid(label, NOW - 1000), "from": BPH, "identity": BOB, "to": to, "scope": ["dsip.subscribe"],
             "valid_until": NOW + 86400}
        if audience is not None:
            g["presence_audience"] = audience
        return g

    def subscribe(label, frm, g=None, sealed=True):
        m = {"type": "subscribe", "id": uid(label, NOW), "from": frm, "to": AUTH, "target": BOB, "events": ["presence"],
             "expires_in": 3600}
        if sealed:
            m["profiles"] = ["presence/0.1", P02]
        if g is not None:
            m["claims"] = [{"type": "dsip-grant", "grant": g}]
        return m

    def notify(sub, seq, b):
        return {"send": {"type": "notify", "to": sub["from"], "subscription": sub["id"], "seq": seq, "state": "active",
                         "body": b}}

    def error(r, reason, **extra):
        return {"send": {"type": "error", "to": r["from"], "in_reply_to": r["id"], "reason": reason, **extra}}

    bind = lambda d: {"relay": "bind", "device": d, "identity": BOB}
    out = []

    # P§12.6 / D6: a subscription that did not list presence/0.2 is not given sealed records
    a = subscribe("sl-a", APH, grant("sl-ga", ALICE))
    c = subscribe("sl-c", CPH, grant("sl-gc", CAROL), sealed=False)
    r1 = rec("sl-r1")
    out.append(trace("presence-sealed-by-profile", "Bob's phone is bound and publishes a sealed record. Alice's "
                     "subscription listed presence/0.2 and is given it, and Bob's phone, holding a record she sees, no "
                     "longer counts in her assertion. Carol's did not list presence/0.2: she is given no sealed record, so "
                     "the phone counts in her assertion as before, her body does not change, and she is not notified "
                     "(P§12.6, spec-gap 156).", ["P§12.6", "P§6"], [
        step(bind(BPH), []),
        step({"recv": a}, [notify(a, 1, body("available"))]),
        step({"recv": c}, [notify(c, 1, body("available"))]),
        step({"recv": r1}, [notify(a, 2, body("offline", r1))],
             presence={BOB: {BPH: {"seq": 1, "kid": "main.0", "expires_at": NOW + 300}}},
             subscriptions={
                 a["id"]: {"subscriber": ALICE, "target": BOB, "events": ["presence"], "seq": 2, "expires_at": NOW + 3600,
                           "grant": a["claims"][0]["grant"]["id"], "sealed": True},
                 c["id"]: {"subscriber": CAROL, "target": BOB, "events": ["presence"], "seq": 1, "expires_at": NOW + 3600,
                           "grant": c["claims"][0]["grant"]["id"]}}),
    ]))

    # D6 per audience: one audience sealed, another plain; the subject's own view follows the same profile rule
    af = subscribe("sa-a", APH, grant("sa-ga", ALICE, FAMILY))
    cw = subscribe("sa-c", CPH, grant("sa-gc", CAROL, "work"), sealed=False)
    own = subscribe("sa-own", BLA, sealed=False)
    rf = rec("sa-rf", audience=FAMILY, kid=f"{FAMILY}.0")
    rw = rec("sa-rw", audience="work", state="away")
    out.append(trace("presence-sealed-audience-beside-plain", "Bob's phone publishes a sealed record for his family "
                     "audience and a plain one for work. Alice (family, presence/0.2) is given the sealed one, Carol (work, "
                     "presence/0.1 only) the plain one. Bob's laptop watches its own identity without presence/0.2: it "
                     "sees every audience, but no sealed record, so it is given only the plain work record (P§12.6).",
                     ["P§12.6", "P§6"], [
        step(bind(BPH), []),
        step({"recv": af}, [notify(af, 1, body("available"))]),
        step({"recv": cw}, [notify(cw, 1, body("available"))]),
        step({"recv": own}, [notify(own, 1, body("available"))]),
        step({"recv": rf}, [notify(af, 2, body("offline", rf))]),
        step({"recv": rw}, sorted([notify(cw, 2, body("offline", rw)), notify(own, 2, body("offline", rw))],
                                  key=lambda e: e["send"]["subscription"]),
             presence={BOB: {f"{BPH}/{FAMILY}": {"seq": 1, "kid": f"{FAMILY}.0", "expires_at": NOW + 300},
                             f"{BPH}/work": {"seq": 1, "state": "away", "expires_at": NOW + 300}}}),
    ]))

    # P§12.6: P§3's checks read only fields in clear, so they apply to sealed records unchanged
    s1, s1b, s2 = rec("sc-1", seq=4), rec("sc-1b", seq=4, kid="main.1"), rec("sc-2", seq=5)
    s3 = rec("sc-3", seq=6, at=NOW + 5)
    out.append(trace("presence-sealed-checked-as-plain", "Sealed records are checked as plain ones: a second record "
                     "with the same seq is stale whatever its kid, a newer one within 5 s is rate-limited, and one 5 s "
                     "later is accepted (P§3, P§8, P§12.6).", ["P§12.6", "P§3", "P§8"], [
        step(bind(BPH), []),
        step({"recv": s1}, []),
        step({"recv": s1b}, [error(s1b, "presence.stale")]),
        step({"recv": s2}, [error(s2, "policy.rate-limited", retry_after=5)]),
        step({"advance": 5}, []),
        step({"recv": s3}, [], presence={BOB: {BPH: {"seq": 6, "kid": "main.0", "expires_at": NOW + 305}}}),
    ]))
    return out
