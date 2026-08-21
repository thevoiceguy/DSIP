"""Stages 12–14: version negotiation, schema dispatch, stateless semantic checks.

Spec: §11, §10.3, §9.3, §13.2, §14.2, §15, §19.4; schema README checks 1, 2, 5, 7, 8, 9, 11.
"""
from __future__ import annotations

from typing import Any

from .registry import (resolve_reason, effective_answered_by, effective_progress_status, effective_integrity,
                       SUBSCRIPTION_EVENTS, REASON_BEARING_TYPES, INTEGRITY_MODES)
from .schema import schema_errors, dispatch_type
from .verdict import Verdict

INTRODUCTION_MAX_BYTES = 4096  # §19.4
DIRECTION_ANSWERS = {         # Impl (spec-gap 9): SDP-style offer→answer direction compatibility
    "sendrecv": {"sendrecv", "sendonly", "recvonly", "inactive"},
    "sendonly": {"recvonly", "inactive"},
    "recvonly": {"sendonly", "inactive"},
    "inactive": {"inactive"},
}


def _ver(s: str) -> tuple[int, int] | None:
    try:
        a, b = s.split(".")
        return int(a), int(b)
    except (ValueError, AttributeError):
        return None


def check_version(payload: dict, supported: dict) -> Verdict:
    """§11.2 compatibility rules. Malformed blocks are left to the schema stage."""
    blk = payload.get("dsip")
    if not isinstance(blk, dict):
        return Verdict.accept()
    core, min_core = _ver(blk.get("core")), _ver(blk.get("min_core"))
    mine = _ver(supported.get("core", "1.0"))
    if core is None or min_core is None or mine is None:
        return Verdict.accept()
    # Major versions are incompatible by default; the sender's floor must not exceed ours.
    if core[0] != mine[0] or min_core > mine:
        return Verdict.reject("version-unsupported", "session.unsupported-core-version")
    known = set(supported.get("profiles", [])) | set(supported.get("extensions", []))
    crit = blk.get("critical")
    if isinstance(crit, list):
        for c in crit:
            if c not in known:  # §11.2: unknown critical extensions require rejection
                return Verdict.reject("version-unsupported", "session.unsupported-critical-extension")
    profiles = blk.get("profiles")
    if isinstance(profiles, list) and profiles and not any(p in known for p in profiles):
        return Verdict.reject("version-unsupported", "session.unsupported-profile-version")
    return Verdict.accept()


def check_schema(payload: dict) -> Verdict:
    t = dispatch_type(payload)
    if t is None:
        return Verdict.reject("unknown-type")
    errs = schema_errors(t, payload)
    if errs:
        return Verdict.reject("schema-invalid", detail=errs[0][:200])
    return Verdict.accept()


def selection_is_subset(selection: dict, offer: dict) -> bool:
    """Check 9 (Impl, spec-gap 9)."""
    offered_media = offer.get("media", []) or []
    for sel in selection.get("media", []) or []:
        match = None
        for off in offered_media:
            if off.get("type") == sel.get("type") and off.get("purpose") == sel.get("purpose"):
                match = off
                break
        if match is None:
            return False
        offered_codecs = {c.get("id") for c in match.get("codecs", [])}
        if any(c.get("id") not in offered_codecs for c in sel.get("codecs", [])):
            return False
        if sel.get("direction") not in DIRECTION_ANSWERS.get(match.get("direction"), set()):
            return False
    offered_transports = {t.get("id") for t in offer.get("transports", []) or []}
    for t in selection.get("transports", []) or []:
        if t.get("id") not in offered_transports:
            return False
    return True


def check_semantic(payload: dict, ctx: dict, encoded_size: int | None = None) -> Verdict:
    """Stage 14. `ctx` is the raw vector context dict."""
    t = payload["type"]
    if t == "hello" and "in_reply_to" in payload and ctx.get("sent_hello_id") is not None:
        if payload["in_reply_to"] != ctx["sent_hello_id"]:  # §13.2 / §20.5 anti-splicing
            return Verdict.reject("hello-in-reply-to-mismatch")
    if t == "answer" and isinstance(ctx.get("offer"), dict):
        if not selection_is_subset(payload, ctx["offer"]):
            return Verdict.reject("selection-not-subset")
    if t == "subscribe":
        for ev in payload.get("events", []):
            cap = SUBSCRIPTION_EVENTS.get(ev)
            if cap is not None and payload["expires_in"] > cap:  # §9.3 hard caps → error policy.subscription-lifetime (v0.7)
                return Verdict.reject("subscription-lifetime-exceeded", "policy.subscription-lifetime")
    if t == "introduction":
        size = encoded_size if encoded_size is not None else ctx.get("encoded_size")
        if size is not None and size > INTRODUCTION_MAX_BYTES:  # §19.4
            return Verdict.reject("introduction-too-large")
    if t == "grant" and isinstance(ctx.get("known_introductions"), list):
        if payload["session"] not in ctx["known_introductions"]:  # §19.4
            return Verdict.reject("grant-unknown-introduction")
    if t == "key-rotation":  # §7.5 (v0.7, spec-gap 22)
        if payload["subject"] != payload["from"]:
            return Verdict.reject("rotation-subject-mismatch")
        if payload["next"] == payload["previous"]:
            return Verdict.reject("rotation-next-same-as-previous")
        signer = ctx.get("signer_kid")
        if signer is not None and not payload.get("recovery", False) and signer != payload["previous"]:
            return Verdict.reject("rotation-signer-not-previous")
    return Verdict.accept(**registry_effects(payload))


def registry_effects(payload: dict) -> dict:
    """Check 5 — membership with fallback. Never rejects."""
    t = payload["type"]
    eff: dict[str, Any] = {}
    warnings: list[str] = []
    if "reason" in payload and (t in REASON_BEARING_TYPES or t == "notify"):
        r = resolve_reason(payload["reason"], t)
        eff["reason"] = r.effective
        eff["fallback"] = r.fallback
        if not r.valid_on_type:
            warnings.append("reason-not-valid-on-type")
    if t in ("answer", "update") and "answered_by" in payload:
        eff["answered_by"] = effective_answered_by(payload["answered_by"])
    if t == "progress":
        eff["status"] = effective_progress_status(payload["status"])
    if t == "publish" and "integrity" in payload:
        eff["integrity"] = effective_integrity(payload["integrity"])
        if payload["integrity"] not in INTEGRITY_MODES:
            warnings.append("integrity-mode-unknown")  # §22.2 registry fallback
    out: dict[str, Any] = {}
    if eff:
        out["effective"] = eff
    if warnings:
        out["warnings"] = warnings
    return out


def check_payload(payload: dict, ctx: dict, encoded_size: int | None = None) -> Verdict:
    """Stages 12–14 in order."""
    for v in (check_version(payload, ctx.get("supported") or {"core": "1.0", "profiles": ["interactive-media/1.0"], "extensions": []}),
              check_schema(payload)):
        if not v.ok:
            return v
    return check_semantic(payload, ctx, encoded_size)
