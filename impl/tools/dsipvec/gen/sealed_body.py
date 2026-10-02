"""Sealed-body vectors — stage 12b on decoded payloads (§10.4, extension `sealed-body/1.0`; spec-gap 97).

Kind `semantic`. A context with `unseal_key_hex` (the addressee's X25519 private key) is the addressee: it opens
`sealed`, then stages 13–14 run on the merged payload. A context with `router: true` routes: it never opens, the clear part is validated as it stands,
and §11.2's critical-extension rule does not apply (it binds the addressee). Ciphertexts are deterministic (the ephemeral key is derived from the vector label).
"""
from __future__ import annotations

import copy
import json

from .. import fixtures as F
from ..crypto import b64url_encode
from ..messaging import hpke_derive_sk, hpke_seal, x25519_public
from ..semantic import SEALED_BODY_ALG, SEALED_BODY_EXT, SEALED_BODY_INFO, sealed_body_aad
from .common import NOW, AUDIO_SELECTION, MEDIA_OFFER, ONE_TRANSPORT, invite, session_msg, vector, accept, reject

BOB_KA_SK = hpke_derive_sk(b"dsip vectors: bob key agreement")
ALICE_KA_SK = hpke_derive_sk(b"dsip vectors: alice key agreement")
MALLORY_KA_SK = hpke_derive_sk(b"dsip vectors: mallory key agreement")
SUPPORTED = {**F.SUPPORTED, "extensions": [*F.SUPPORTED.get("extensions", []), SEALED_BODY_EXT]}
INVITE_SEALABLE = ["identity", "intent", "media", "policy", "transports"]


def padded(body: dict, pad: int = 256) -> bytes:
    raw = json.dumps(body, separators=(",", ":")).encode()
    return raw + b" " * (-len(raw) % pad or 0)


def seal(payload: dict, fields: list[str], to_sk: bytes, label: str, *, plaintext: bytes | None = None,
         alg: str = SEALED_BODY_ALG, critical: bool = True, aad_from: dict | None = None) -> dict:
    """Move `fields` into `sealed` (or seal `plaintext` verbatim), as a §10.4 sender would."""
    p = copy.deepcopy(payload)
    body = {f: p.pop(f) for f in fields}
    pt = plaintext if plaintext is not None else padded(body)
    enc, ct = hpke_seal(x25519_public(to_sk), SEALED_BODY_INFO, sealed_body_aad(aad_from or p), pt,
                        hpke_derive_sk(b"dsip vectors: ephemeral " + label.encode()))
    p["sealed"] = {"alg": alg, "enc": b64url_encode(enc), "ct": b64url_encode(ct)}
    p["dsip"] = {**p["dsip"], "extensions": [*p["dsip"]["extensions"], SEALED_BODY_EXT]}
    if critical:
        p["dsip"]["critical"] = [*p["dsip"]["critical"], SEALED_BODY_EXT]
    return p


def sv(vid, desc, payload, expect, *, key: bytes | None = BOB_KA_SK, refs=("§10.4",), **ctx):
    context = {"now": NOW, "supported": SUPPORTED}
    if key is not None:
        context["unseal_key_hex"] = key.hex()
    context.update(ctx)
    return vector(f"semantic/{vid}", "semantic", desc, list(refs), context, {"payload": payload}, expect)


def vectors() -> list[dict]:
    out = []
    inv = invite("sb-inv")
    sid = inv["id"]
    sealed_inv = seal(inv, INVITE_SEALABLE, BOB_KA_SK, "inv")

    # --- the addressee opens, then stages 13–14 run on the merged payload
    out.append(sv("sealed-invite-opens", "Every sealable invite field sealed to bob's key agreement key: opens, merges, validates.",
                  sealed_inv, accept(effective={"sealed": INVITE_SEALABLE})))
    out.append(sv("sealed-invite-partial", "Only the identity claims sealed; media and transports stay in clear.",
                  seal(inv, ["identity"], BOB_KA_SK, "inv-partial"), accept(effective={"sealed": ["identity"]})))
    ans = session_msg("answer", "sb-ans", sid, F.did("bob-phone"), inv["from"], at=NOW + 2, answered_by="user",
                      media=copy.deepcopy(AUDIO_SELECTION), transports=copy.deepcopy(ONE_TRANSPORT))
    out.append(sv("sealed-answer-opens-selection-checked",
                  "An answer sealed to alice's key: after opening, the selection ⊆ offer check runs on the sealed media.",
                  seal(ans, ["answered_by", "media", "transports"], ALICE_KA_SK, "ans"),
                  accept(effective={"answered_by": "user", "sealed": ["answered_by", "media", "transports"]}),
                  key=ALICE_KA_SK, offer=copy.deepcopy(inv)))
    bad_ans = {**ans, "media": [{**AUDIO_SELECTION[0], "codecs": [{"id": "codec:audio/g729"}]}]}
    out.append(sv("sealed-answer-selection-not-subset",
                  "A sealed answer selecting a codec the offer never carried: stage 14 rejects it once opened.",
                  seal(bad_ans, ["answered_by", "media", "transports"], ALICE_KA_SK, "ans-bad"),
                  reject("selection-not-subset"), key=ALICE_KA_SK, offer=copy.deepcopy(inv)))
    dtmf = session_msg("info", "sb-dtmf", sid, inv["from"], F.BOB_WEB, at=NOW + 5, about="media:dtmf",
                       data={"digits": "1234#"})
    out.append(sv("sealed-info-dtmf-opens", "DTMF digits (an IVR PIN) sealed: the binding and the digits travel inside the seal.",
                  seal(dtmf, ["about", "data"], BOB_KA_SK, "dtmf"), accept(effective={"sealed": ["about", "data"]})))
    bye = session_msg("bye", "sb-bye", sid, inv["from"], F.BOB_WEB, at=NOW + 9, reason="user.hangup", detail="Talk tomorrow")
    out.append(sv("sealed-bye-detail-opens", "A bye's free-text detail sealed; its reason token stays in clear for the relay.",
                  seal(bye, ["detail"], BOB_KA_SK, "bye"),
                  accept(effective={"reason": "user.hangup", "fallback": "none", "sealed": ["detail"]})))

    # --- a router has no key: the clear part is what it validates
    out.append(sv("sealed-invite-routed", "A relay routes a sealed invite without the key: the clear part passes the schema.",
                  sealed_inv, accept(), key=None, router=True))
    out.append(sv("sealed-invite-routed-without-extension",
                  "A relay that does not implement sealed-body/1.0 still routes it: the critical rule binds the addressee (§10.4).",
                  sealed_inv, accept(), key=None, supported=F.SUPPORTED, router=True))
    nothing = {k: v for k, v in inv.items() if k not in ("media", "transports")}
    out.append(sv("clear-invite-without-media-rejected", "Neither sealed nor carrying media and transports: the schema still requires them.",
                  nothing, reject("schema-invalid"), key=None))

    # --- the addressee does not implement the extension
    out.append(sv("sealed-extension-unsupported", "An addressee without sealed-body/1.0 rejects it as an unknown critical extension.",
                  sealed_inv, reject("version-unsupported", "session.unsupported-critical-extension"), key=None,
                  supported=F.SUPPORTED, refs=("§10.4", "§11.2", "§11.3")))

    # --- stage 12b refusals, in order
    out.append(sv("sealed-not-critical", "sealed present but sealed-body/1.0 is not listed in dsip.critical.",
                  seal(inv, INVITE_SEALABLE, BOB_KA_SK, "inv-nc", critical=False), reject("sealed-not-critical")))
    out.append(sv("sealed-alg-unknown", "An alg other than hpke-base-x25519-sha256-aes128gcm.",
                  seal(inv, INVITE_SEALABLE, BOB_KA_SK, "inv-alg", alg="hpke-base-x448-sha512-aes256gcm"),
                  reject("sealed-alg-unsupported")))
    tampered = copy.deepcopy(sealed_inv)
    ct = tampered["sealed"]["ct"]
    tampered["sealed"]["ct"] = ct[:-2] + ("A" if ct[-2] != "A" else "B") + ct[-1]
    out.append(sv("sealed-ct-tampered", "One ciphertext character changed: AES-GCM authentication fails.", tampered,
                  reject("body-unseal-failed")))
    out.append(sv("sealed-wrong-key", "Sealed to mallory's key, opened with bob's.",
                  seal(inv, INVITE_SEALABLE, MALLORY_KA_SK, "inv-wrong"), reject("body-unseal-failed")))
    other = invite("sb-other", at=NOW + 1)
    moved = copy.deepcopy(other)
    moved["sealed"] = copy.deepcopy(sealed_inv["sealed"])
    moved["dsip"] = copy.deepcopy(sealed_inv["dsip"])
    for f in INVITE_SEALABLE:
        moved.pop(f)
    out.append(sv("sealed-moved-to-another-message", "The seal of one invite pasted into another: the AAD binds it to its id.",
                  moved, reject("body-unseal-failed")))
    out.append(sv("sealed-plaintext-not-padded", "A valid object whose length is not a multiple of 256 bytes.",
                  seal(inv, ["identity"], BOB_KA_SK, "inv-pad",
                       plaintext=json.dumps({"identity": inv["identity"]}).encode()),
                  reject("sealed-plaintext-invalid")))
    out.append(sv("sealed-plaintext-array", "The plaintext is a JSON array, not an object.",
                  seal(inv, ["identity"], BOB_KA_SK, "inv-arr", plaintext=b"[]" + b" " * 254), reject("sealed-plaintext-invalid")))
    out.append(sv("sealed-plaintext-empty-object", "An empty object seals nothing.",
                  seal(inv, [], BOB_KA_SK, "inv-empty", plaintext=b"{}" + b" " * 254), reject("sealed-plaintext-invalid")))
    out.append(sv("sealed-plaintext-float", "A float inside the seal breaks §10.3 like one in clear.",
                  seal(inv, ["identity"], BOB_KA_SK, "inv-float", plaintext=padded({"identity": inv["identity"], "intent": 1.5})),
                  reject("sealed-plaintext-invalid")))
    out.append(sv("sealed-routing-field-inside", "A routing field (reason) sealed: only the type's sealable fields may travel inside.",
                  seal(bye, [], BOB_KA_SK, "bye-reason", plaintext=padded({"detail": "x", "reason": "user.busy"})),
                  reject("sealed-field-not-sealable")))
    out.append(sv("sealed-field-also-in-clear", "media sealed and also left in clear: which one counts would be ambiguous.",
                  {**seal(inv, INVITE_SEALABLE, BOB_KA_SK, "inv-dup"), "media": copy.deepcopy(MEDIA_OFFER)},
                  reject("sealed-field-in-clear")))
    bad_media = seal(inv, [], BOB_KA_SK, "inv-badmedia",
                     plaintext=padded({"media": [{"type": "audio"}], "transports": inv["transports"]}))
    for f in ("media", "transports"):
        bad_media.pop(f)
    out.append(sv("sealed-opens-then-schema-invalid", "Opens cleanly, but the sealed media descriptor lacks direction and codecs.",
                  bad_media, reject("schema-invalid")))

    # --- edges settled after the second implementation's reading (spec-gap 97)
    no_to = {k: v for k, v in sealed_inv.items() if k != "to"}
    out.append(sv("sealed-aad-input-missing", "No `to`: the AAD cannot be formed, so the seal is not opened and the schema rejects the payload.",
                  no_to, reject("schema-invalid")))
    odd_crit = copy.deepcopy(sealed_inv)
    odd_crit["dsip"]["critical"] = SEALED_BODY_EXT
    out.append(sv("sealed-critical-not-an-array", "dsip.critical is a string, not an array: it lists nothing.",
                  odd_crit, reject("sealed-not-critical")))
    ntf = session_msg("notify", "sb-ntf", sid, inv["from"], F.BOB_WEB, at=NOW + 3, event="presence")
    out.append(sv("sealed-on-unsealable-type", "A sealed notify: a type with no sealable fields admits none.",
                  seal(ntf, [], BOB_KA_SK, "ntf", plaintext=padded({"detail": "x"})), reject("sealed-field-not-sealable")))
    out.append(sv("sealed-plaintext-looks-like-a-verdict",
                  "A plaintext that happens to read like a verdict object is still just an object with unsealable keys.",
                  seal(inv, ["identity"], BOB_KA_SK, "inv-verdict",
                       plaintext=padded({"verdict": "reject", "code": "payload-float"})),
                  reject("sealed-field-not-sealable")))
    return out
