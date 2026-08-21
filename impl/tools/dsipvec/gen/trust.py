"""`trust/` vectors — §18.1 verification basis, tel-caller headline, gateway.downgraded summary."""
from __future__ import annotations

from .common import vector

GW = "did:web:gw.example"
BOB_WEB = "did:web:example.com:users:bob"


def tv(vid, desc, refs, inp, expect):
    return vector(f"trust/{vid}", "trust", desc, refs, {}, inp, expect)


def tel(number="+15551234567", attest="A", verified=True, verifier=GW, cnam=None):
    c = {"type": "tel", "number": number, "attestation": attest, "verified": verified, "verifier": verifier}
    if cnam:
        c["cnam"] = cnam
    return c


def vectors() -> list[dict]:
    out = []
    # basis: tel wins, then method
    out.append(tv("basis-tel-attestation-a-verified", "A verified attestation-A tel claim yields the gateway-attested basis.", ["§18.1"],
                  {"check": "basis", "identity": GW, "claims": [tel()]},
                  "Gateway attested by gw.example · STIR attestation A (verified)"))
    out.append(tv("basis-tel-unverified", "attestation B not verified → unverified.", ["§18.1", "§20.4"],
                  {"check": "basis", "identity": GW, "claims": [tel(attest="B", verified=False)]},
                  "Gateway attested by gw.example · STIR attestation B (unverified)"))
    out.append(tv("basis-tel-no-attestation", "No attestation → the honest 'no attestation' basis.", ["§18.1"],
                  {"check": "basis", "identity": GW, "claims": [tel(attest="none", verified=False)]},
                  "Gateway attested by gw.example · no attestation"))
    out.append(tv("basis-did-web", "A did:web identity with no tel claim → domain verified.", ["§18.1"],
                  {"check": "basis", "identity": BOB_WEB, "claims": []},
                  "Domain verified (did:web:example.com:users:bob)"))
    out.append(tv("basis-did-key", "A did:key identity → self-issued.", ["§18.1", "§19.1"],
                  {"check": "basis", "identity": "did:key:z6MkAlicePhone", "claims": []}, "Self-issued identity"))
    out.append(tv("basis-tel-over-did-web", "A gateway (did:web) carrying a tel claim shows the caller's basis, not the gateway's domain.", ["§18.1"],
                  {"check": "basis", "identity": GW, "claims": [{"type": "brand", "x": 1}, tel()]},
                  "Gateway attested by gw.example · STIR attestation A (verified)"))
    out.append(tv("basis-unknown-method", "An unrecognized DID method.", ["§18.1"],
                  {"check": "basis", "identity": "did:example:xyz", "claims": []}, "Unrecognized identity method"))
    # tel caller headline
    out.append(tv("tel-caller-with-cnam", "Caller headline with CNAM.", ["§18.1", "§18.2"],
                  {"check": "tel-caller", "claim": tel(cnam="ACME Corp")}, "PSTN caller +15551234567 · ACME Corp"))
    out.append(tv("tel-caller-no-cnam", "Caller headline, number only.", ["§18.1"],
                  {"check": "tel-caller", "claim": tel()}, "PSTN caller +15551234567"))
    out.append(tv("tel-caller-not-tel", "A non-tel claim yields no caller line.", ["§18.1"],
                  {"check": "tel-caller", "claim": {"type": "brand"}}, None))
    # downgrade summary
    out.append(tv("downgrade-plain-trunk", "Three losses on a plain-RTP outbound crossing.", ["§6.3"],
                  {"check": "downgrade", "losses": ["no-srtp-on-trunk", "identity-not-assertable", "policy-unenforceable"]},
                  "Trust downgraded crossing the gateway (§6.3): media is not encrypted on the PSTN trunk; your identity could not be asserted into the PSTN; your media policy cannot be enforced past the gateway"))
    out.append(tv("downgrade-no-attestation", "Inbound, no attestation.", ["§6.3", "§18.1"],
                  {"check": "downgrade", "losses": ["no-attestation"]},
                  "Trust downgraded crossing the gateway (§6.3): the caller carried no verified attestation"))
    out.append(tv("downgrade-empty", "Downgrade with no named losses.", ["§6.3"],
                  {"check": "downgrade", "losses": []}, "Trust downgraded crossing the gateway (§6.3)"))
    return out
