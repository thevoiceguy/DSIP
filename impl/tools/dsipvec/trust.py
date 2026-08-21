"""§18.1 trust rendering — reference for the `trust/` vectors.

Spec: §18.1 (verification basis, never a badge), §6.3 / Gateway Profile G§7 (gateway.downgraded
losses), G§5 (a PSTN caller's tel-claim basis). Mirrors dsip_core::trust; both are pinned by the
same vectors so the string a callee sees is defined once.
"""
from __future__ import annotations

from typing import Any


def tel_basis(claim: dict) -> str | None:
    if claim.get("type") != "tel":
        return None
    verifier = claim.get("verifier")
    if not isinstance(verifier, str):
        return None
    host = verifier[len("did:web:"):] if verifier.startswith("did:web:") else verifier
    attestation = claim.get("attestation") or "none"
    verified = bool(claim.get("verified")) and attestation != "none"
    if verified:
        return f"Gateway attested by {host} · STIR attestation {attestation} (verified)"
    if attestation != "none":
        return f"Gateway attested by {host} · STIR attestation {attestation} (unverified)"
    return f"Gateway attested by {host} · no attestation"


def verification_basis(identity: str, claims: list) -> str:
    for c in claims:
        if isinstance(c, dict) and c.get("type") == "tel":
            b = tel_basis(c)
            if b is not None:
                return b
    if identity.startswith("did:web:"):
        return f"Domain verified (did:web:{identity[len('did:web:'):]})"
    if identity.startswith("did:key:"):
        return "Self-issued identity"
    return "Unrecognized identity method"


def tel_caller_line(claim: dict) -> str | None:
    if claim.get("type") != "tel":
        return None
    number = claim.get("number")
    if not isinstance(number, str):
        return None
    cnam = claim.get("cnam")
    return f"PSTN caller {number} · {cnam}" if isinstance(cnam, str) else f"PSTN caller {number}"


_PHRASE = {
    "no-srtp-on-trunk": "media is not encrypted on the PSTN trunk",
    "identity-not-assertable": "your identity could not be asserted into the PSTN",
    "no-attestation": "the caller carried no verified attestation",
    "policy-unenforceable": "your media policy cannot be enforced past the gateway",
}


def downgrade_summary(losses: list) -> str:
    if not losses:
        return "Trust downgraded crossing the gateway (§6.3)"
    phrases = [_PHRASE.get(l, "an unspecified guarantee was lost") for l in losses]
    return "Trust downgraded crossing the gateway (§6.3): " + "; ".join(phrases)


def run(v: dict) -> Any:
    inp = v["input"]
    check = inp["check"]
    if check == "basis":
        return verification_basis(inp.get("identity", ""), inp.get("claims", []))
    if check == "tel-caller":
        return tel_caller_line(inp["claim"])
    if check == "downgrade":
        return downgrade_summary(inp.get("losses", []))
    raise ValueError(f"unknown trust check {check}")
