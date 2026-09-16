"""DSIP-JOSE envelope: construct, sign, and the verification pipeline (spec §10.2, §7.4, §12.9, §20.6).

Pipeline stages 1–11 of vectors/README.md. The payload is carried as bytes
through signature verification and only then decoded — never re-serialized.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .crypto import (KeyPair, b64url_decode, b64url_encode, ed25519_verify,
                     public_from_did_key, b58_decode, ED25519_PUB_MULTICODEC)
from .verdict import Verdict
from .wire import parse_payload, DID_RE
from . import ulid as ulid_mod

REPLAY_WINDOW_S = 300          # §12.9
ULID_TOLERANCE_S = 300         # §20.6, Impl: tolerance = replay window (spec-gap 6)
INTRODUCTION_MAX_VALIDITY_S = 604800  # §19.4; Impl: enforced at stage 9 (spec-gap 31)
WS_MAX_ENVELOPE_BYTES = 65536  # §13.2
SIGNALING_CAPABILITY = "dsip.signaling"


# ---------------------------------------------------------------- construction

def protected_header(kid: str, alg: str = "EdDSA", **extra) -> dict:
    h = {"alg": alg, "kid": kid, "typ": "dsip+json"}
    h.update(extra)
    return h


def encode_payload(payload: dict) -> bytes:
    """Compact UTF-8 JSON. Field order is whatever the dict holds; the signature covers these bytes."""
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign_bytes(payload_bytes: bytes, signer: KeyPair, kid: str, header_extra: dict | None = None,
               alg: str = "EdDSA") -> dict:
    header = protected_header(kid, alg, **(header_extra or {}))
    prot = b64url_encode(encode_payload(header))
    pay = b64url_encode(payload_bytes)
    sig = signer.sign(f"{prot}.{pay}".encode("ascii"))
    return {"protected": prot, "payload": pay, "signature": b64url_encode(sig)}


def sign(payload: dict, signer: KeyPair, kid: str, header_extra: dict | None = None, alg: str = "EdDSA") -> dict:
    return sign_bytes(encode_payload(payload), signer, kid, header_extra, alg)


def frame(envelope: dict) -> str:
    """The ws/1.0 text frame for an envelope (§13.2 framing)."""
    return json.dumps(envelope, separators=(",", ":"))


# ---------------------------------------------------------------- resolution (§8.1)

@dataclass
class Context:
    now: int
    did_documents: dict[str, dict] = field(default_factory=dict)
    delegations: list[dict] = field(default_factory=list)
    seen_ids: set[str] = field(default_factory=set)
    supported: dict[str, Any] = field(default_factory=lambda: {"core": "1.0", "profiles": [], "extensions": []})
    revocations: list = field(default_factory=list)

    @staticmethod
    def from_vector(ctx: dict) -> "Context":
        return Context(
            now=ctx.get("now", 0),
            did_documents=ctx.get("did_documents", {}) or {},
            delegations=list(ctx.get("delegations", []) or []),
            seen_ids=set(ctx.get("seen_ids", []) or []),
            supported=ctx.get("supported") or {"core": "1.0", "profiles": ["interactive-media/1.0"], "extensions": []},
            revocations=list(ctx.get("revocations", []) or []),
        )


def split_kid(kid: str) -> tuple[str, str] | None:
    if not isinstance(kid, str) or "#" not in kid:
        return None
    did, frag = kid.split("#", 1)
    if not DID_RE.match(did) or frag == "":
        return None
    return did, frag


def _multibase_to_ed25519(mb: str) -> bytes | None:
    if not isinstance(mb, str) or not mb.startswith("z"):
        return None
    try:
        raw = b58_decode(mb[1:])
    except ValueError:
        return None
    if raw[:2] != ED25519_PUB_MULTICODEC or len(raw) != 34:
        return None
    return raw[2:]


def resolve_kid(kid: str, ctx: Context) -> bytes | None:
    """DID URL → Ed25519 public key, or None. Authority: DID document only (§8.1 rule 4)."""
    parts = split_kid(kid)
    if parts is None:
        return None
    did, frag = parts
    if did.startswith("did:key:"):
        # Self-certifying: the only verification method is the key itself; fragment must name it.
        if frag != did[len("did:key:"):]:
            return None
        try:
            return public_from_did_key(did)
        except ValueError:
            return None
    doc = ctx.did_documents.get(did)
    if not isinstance(doc, dict):
        return None
    for vm in doc.get("verificationMethod", []) or []:
        if not isinstance(vm, dict):
            continue
        vid = vm.get("id")
        if vid == kid or vid == f"#{frag}":
            if vm.get("controller") not in (None, did):
                return None
            return _multibase_to_ed25519(vm.get("publicKeyMultibase"))
    return None


# ---------------------------------------------------------------- raw verify (stages 2–6)

@dataclass
class Verified:
    header: dict
    payload: dict
    payload_bytes: bytes
    signer_did: str
    kid: str


def verify_raw(envelope: Any, ctx: Context, core_shape: bool = True) -> tuple[Verdict, Verified | None]:
    """Stages 2–6: shape, header, kid resolution, signature, payload parse. No binding, no timing.

    `core_shape=False` skips the DSIP core-field check (used for delegation credentials,
    whose payload is a DeviceDelegation object, not a message)."""
    if not isinstance(envelope, dict) or set(envelope.keys()) != {"protected", "payload", "signature"}:
        return Verdict.reject("envelope-shape"), None
    try:
        prot_b, pay_b, sig_b = (b64url_decode(envelope[k]) if isinstance(envelope[k], str) else None
                                for k in ("protected", "payload", "signature"))
    except ValueError:
        return Verdict.reject("envelope-shape"), None
    if prot_b is None or pay_b is None or sig_b is None:
        return Verdict.reject("envelope-shape"), None
    try:
        header = json.loads(prot_b.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return Verdict.reject("header-invalid"), None
    if not isinstance(header, dict) or not isinstance(header.get("alg"), str) or not isinstance(header.get("kid"), str):
        return Verdict.reject("header-invalid"), None
    if header["alg"] != "EdDSA":
        # §10.2: Ed25519 MUST; ES256 MAY (not implemented here); everything else MUST be rejected.
        return Verdict.reject("alg-unsupported"), None
    parts = split_kid(header["kid"])
    if parts is None:
        return Verdict.reject("kid-invalid"), None
    pub = resolve_kid(header["kid"], ctx)
    if pub is None:
        return Verdict.reject("kid-unresolvable"), None
    signing_input = f"{envelope['protected']}.{envelope['payload']}".encode("ascii")
    if len(sig_b) != 64 or not ed25519_verify(pub, signing_input, sig_b):
        return Verdict.reject("signature-invalid"), None
    v, payload = parse_payload(pay_b, core_shape=core_shape)
    if not v.ok:
        return v, None
    return Verdict.accept(), Verified(header, payload, pay_b, parts[0], header["kid"])


# ---------------------------------------------------------------- delegation (§7.4)

def verify_delegation(deleg: Any, subject: str, device: str, ctx: Context,
                      capability: str = SIGNALING_CAPABILITY) -> Verdict:
    """A delegation envelope is valid for (subject, device) when it is signed directly by a key
    of `subject`, names exactly that subject/device, carries `capability` (dsip.signaling for
    envelopes; dsip.messaging for MLS leaves, Messaging Profile M§6.2), and is live at now."""
    v, ver = verify_raw(deleg, ctx, core_shape=False)
    if not v.ok:
        return Verdict.reject("delegation-invalid", detail=v.code)
    p = ver.payload
    if (p.get("type") != "DeviceDelegation" or p.get("subject") != subject or p.get("device") != device
            or ver.signer_did != subject):
        return Verdict.reject("delegation-invalid")
    caps = p.get("capabilities")
    if not isinstance(caps, list) or capability not in caps:
        return Verdict.reject("delegation-capability")
    ia, ea = p.get("issued_at"), p.get("expires_at")
    if not (isinstance(ia, int) and isinstance(ea, int)) or not (ia <= ctx.now < ea):
        return Verdict.reject("delegation-expired")
    if any(revokes(r, subject, device, ia, ctx) for r in revocations_for(subject, ctx)):
        return Verdict.reject("delegation-revoked")  # spec-gap 57 (v0.8 draft)
    return Verdict.accept()


REVOCATIONS_DOC_FIELD = "dsipDelegationRevocations"


def _as_envelope(r):
    if isinstance(r, str):
        parts = r.split(".")
        return {"protected": parts[0], "payload": parts[1], "signature": parts[2]} if len(parts) == 3 else None
    return r if isinstance(r, dict) else None


def revocations_for(subject: str, ctx: Context) -> list:
    """Every revocation a verifier can see for `subject`: those it holds, and those the subject's DID document
    publishes (authoritative, §8.1). A validly signed revocation only removes authority, so any source counts."""
    doc = ctx.did_documents.get(subject)
    published = doc.get(REVOCATIONS_DOC_FIELD, []) if isinstance(doc, dict) else []
    return [e for e in map(_as_envelope, list(ctx.revocations) + list(published or [])) if e is not None]


def revokes(rev: dict, subject: str, device: str, delegation_issued_at: int, ctx: Context) -> bool:
    """spec-gap 57: a `delegation-revocation` signed directly by a key of `subject` revokes every delegation of
    `device` for `subject` issued at or before its `revoked_at`. The record is a credential: no delivery window."""
    v, ver = verify_raw(rev, ctx, core_shape=False)
    if not v.ok:
        return False
    p = ver.payload
    return (p.get("type") == "delegation-revocation" and p.get("subject") == subject and p.get("from") == subject
            and ver.signer_did == subject and p.get("device") == device and isinstance(p.get("revoked_at"), int)
            and delegation_issued_at <= p["revoked_at"])


def check_binding(subject: str, device: str, presented: list, ctx: Context) -> Verdict:
    """Is `device` authorized to act for `subject`? Direct when equal; else via a presented delegation."""
    if subject == device:
        return Verdict.accept()
    candidates = [d for d in presented if isinstance(d, dict) and _names(d) == (subject, device)]
    if not candidates:
        return Verdict.reject("signer-mismatch")
    first_failure = None
    for d in candidates:
        v = verify_delegation(d, subject, device, ctx)
        if v.ok:
            return v
        first_failure = first_failure or v
    return first_failure


def _names(deleg: dict) -> tuple | None:
    try:
        p = json.loads(b64url_decode(deleg["payload"]).decode("utf-8"))
        return (p.get("subject"), p.get("device"))
    except Exception:
        return None


# ---------------------------------------------------------------- full pipeline (stages 1–11)

def verify(envelope: Any, ctx: Context, frame_text: str | None = None) -> tuple[Verdict, Verified | None]:
    """Stages 1–11. On accept, extra carries type/signer/identity."""
    if frame_text is not None and len(frame_text.encode("utf-8")) > WS_MAX_ENVELOPE_BYTES:
        return Verdict.reject("frame-too-large", "transport.envelope-too-large"), None
    v, ver = verify_raw(envelope, ctx)
    if not v.ok:
        return v, None
    p = ver.payload
    msg_type = p["type"]
    hello_reason = "transport.hello-rejected" if msg_type == "hello" else None

    # Stage 7: bind kid → from (→ on_behalf_of on hello)
    presented = list(ctx.delegations) + [d for d in (ver.header.get("delegations") or []) if isinstance(d, dict)]
    b = check_binding(p["from"], ver.signer_did, presented, ctx)
    if not b.ok:
        return Verdict.reject(b.code, hello_reason, b.detail), None
    identity = p["from"]
    if msg_type == "hello" and isinstance(p.get("on_behalf_of"), str):
        b = check_binding(p["on_behalf_of"], p["from"], presented, ctx)
        if not b.ok:
            return Verdict.reject(b.code, hello_reason, b.detail), None
        identity = p["on_behalf_of"]

    # Stage 8–9: expiry ordering, replay window, expiry
    ia, ea = p["issued_at"], p["expires_at"]
    if ea <= ia:
        return Verdict.reject("expiry-order"), None
    if msg_type == "introduction":
        # §19.4: introductions are store-and-forward by design, valid up to 604,800 s. Impl (spec-gap 31):
        # the cap is enforced here, the 300 s age bound is replaced by expires_at (checked next), the
        # future bound stays, and receivers track the id until expires_at.
        if ea - ia > INTRODUCTION_MAX_VALIDITY_S:
            return Verdict.reject("introduction-validity"), None
        if ia > ctx.now + REPLAY_WINDOW_S:
            return Verdict.reject("replay-window"), None
    elif ia < ctx.now - REPLAY_WINDOW_S or ia > ctx.now + REPLAY_WINDOW_S:
        return Verdict.reject("replay-window"), None
    if ea < ctx.now:
        return Verdict.reject("expired", "session.expired" if msg_type == "invite" else None), None
    # Stage 10: dedup
    if p["id"] in ctx.seen_ids:
        return Verdict.reject("duplicate-id"), None
    # Stage 11: ULID timestamp vs issued_at (§20.6)
    if abs(ulid_mod.timestamp_ms(p["id"]) // 1000 - ia) > ULID_TOLERANCE_S:
        return Verdict.reject("ulid-issued-at-mismatch"), None
    return Verdict.accept(type=msg_type, signer=ver.signer_did, identity=identity), ver
