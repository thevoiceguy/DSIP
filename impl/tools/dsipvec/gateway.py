"""SIP/PSTN gateway — reference semantics for the `gateway/` vectors (Phase 4, G0).

Spec: §15.5 (foreign codes MUST be mapped to DSIP reasons, never tunnelled; the normative
table belongs to the Gateway Profile — this module *is* that table, pinned by vectors), §6.3
(crossing the PSTN is a trust downgrade unless identity semantics are preserved), §14.1 (an
`answer` from a gateway is `answered_by: gateway`), §18.1 (verification basis, never a badge),
§19.4 (first contact applies to the gateway identity), §12.5 (cancel/answer race on the SIP
leg), Appendix C (early media: classify or answer and pass through).

Everything here is pure: mapping tables, claim derivation, the downgrade rule, and a minimal
B2BUA controller state machine (`GatewayCall`) that the Rust `dsip-gateway` crate mirrors.
"""
from __future__ import annotations

from typing import Any

from . import binding as B

GATEWAY_DID = "did:web:gw.example"

# ---------------------------------------------------------------- §15.5 inbound: SIP/Q.850 → DSIP

# Q.850 cause (RFC 3326 Reason header) takes precedence over the SIP status when both are present
# and the cause is mapped — the cause is the more specific signal.
Q850_TO_DSIP = {
    1: "identity.unknown", 17: "endpoint.busy", 18: "endpoint.unavailable", 19: "endpoint.unavailable",
    20: "endpoint.unavailable", 21: "user.declined", 22: "identity.not-in-service", 28: "identity.unknown",
    31: "user.hangup", 16: "user.hangup", 34: "gateway.unreachable", 38: "gateway.unreachable",
    41: "gateway.unreachable", 42: "gateway.unreachable", 43: "gateway.unreachable", 44: "gateway.unreachable",
    47: "media.failed", 63: "media.unsupported", 65: "media.unsupported", 79: "media.unsupported",
    102: "session.timeout",
}
SIP_TO_DSIP = {
    403: "policy.blocked", 404: "identity.unknown", 408: "endpoint.unavailable", 410: "identity.not-in-service",
    415: "media.unsupported", 480: "endpoint.unavailable", 484: "identity.unknown", 486: "endpoint.busy",
    487: "session.cancelled", 488: "media.unsupported", 502: "gateway.unreachable", 503: "gateway.unreachable",
    504: "gateway.unreachable", 600: "endpoint.busy", 603: "user.declined", 604: "identity.unknown",
    606: "media.unsupported",
}


def map_inbound(sip_status: int | None, q850: int | None = None, *, phase: str = "pre-answer", moved_to: str | None = None) -> dict:
    """A SIP final response (or BYE Reason) → `(reason, carrying message, detail)`.

    `phase` is the DSIP leg's state: `pre-answer` → `reject`, `active` → `bye`, `transport` → `error`."""
    carry = {"pre-answer": "reject", "active": "bye", "transport": "error"}[phase]
    detail = None
    if q850 is not None and q850 in Q850_TO_DSIP:
        token = Q850_TO_DSIP[q850]
        detail = f"Q.850 {q850}"
    elif sip_status is not None and sip_status in SIP_TO_DSIP:
        token = SIP_TO_DSIP[sip_status]
        detail = f"SIP {sip_status}"
    elif sip_status is None and q850 is None:
        # A BYE with no Reason header is a normal hangup.
        token = "user.hangup"
    else:
        token = "gateway.mapped"
        detail = f"SIP {sip_status}" if sip_status is not None else f"Q.850 {q850}"
    if token == "identity.not-in-service" and moved_to:
        token, detail = "identity.moved", moved_to
    if phase == "active" and token in ("endpoint.busy", "endpoint.unavailable", "identity.unknown", "identity.not-in-service",
                                       "identity.moved", "session.cancelled", "user.declined", "policy.blocked"):
        # These describe a failed attempt; once ACTIVE the honest token for a remote teardown is the mapped one.
        token, detail = "gateway.mapped", detail or token
    out = {"reason": token, "carry": carry}
    if detail is not None:
        out["detail"] = detail
    return out


# ---------------------------------------------------------------- §15.5 outbound: DSIP → SIP

# (status, Q.850 cause or None). Every crossing also carries `Reason: DSIP;text="<token>"` so the far
# side (or a capture) can see the unmapped DSIP reason — a Gateway Profile proposal.
DSIP_TO_SIP = {
    "user.declined": (603, 21), "user.no-answer": (480, 19), "user.blocked": (603, 21), "user.cancelled": (487, None),
    "endpoint.busy": (486, 17), "endpoint.unavailable": (480, 18), "endpoint.capability": (488, 79),
    "identity.not-in-service": (410, 22), "identity.moved": (410, 22), "identity.suspended": (403, 21), "identity.unknown": (404, 1),
    "session.expired": (480, 102), "session.timeout": (480, 102), "session.failed": (500, 41),
    "media.unsupported": (488, 65), "media.offer-required": (488, 65), "media.encryption-required": (488, 65),
    "policy.blocked": (403, 21), "policy.trust-insufficient": (403, 21), "policy.first-contact-required": (403, 21),
    "policy.rate-limited": (503, 42), "policy.terminated": (480, 31),
    "transport.envelope-too-large": (503, 41), "transport.hello-required": (503, 41), "transport.hello-rejected": (503, 41),
    "transport.routing-refused": (503, 41), "transport.unknown-recipient": (404, 1), "transport.rate-limited": (503, 42),
    "gateway.unreachable": (503, 38), "gateway.mapped": (500, 41),
}
BYE_CAUSES = {"user.hangup": 16, "session.already-answered": 16, "session.cancelled": 16, "media.failed": 47, "policy.terminated": 31}


def map_outbound(token: str, *, phase: str = "pre-answer") -> dict:
    """A DSIP reason → what the SIP leg sends: a final response (pre-answer) or a BYE (active)."""
    reason_hdr = {"protocol": "DSIP", "text": token}
    if phase == "active":
        cause = BYE_CAUSES.get(token, DSIP_TO_SIP.get(token, (None, 16))[1] or 16)
        return {"method": "BYE", "q850": cause, "reason_header": reason_hdr}
    if token in DSIP_TO_SIP:
        status, cause = DSIP_TO_SIP[token]
    else:
        category = token.split(".", 1)[0]
        status, cause = {"user": (603, 21), "endpoint": (480, 18), "identity": (404, 1), "session": (500, 41),
                         "media": (488, 65), "policy": (403, 21), "transport": (503, 41), "gateway": (503, 38)}.get(category, (500, 41))
    out = {"status": status, "reason_header": reason_hdr}
    if cause is not None:
        out["q850"] = cause
    if token in ("policy.rate-limited", "transport.rate-limited"):
        out["retry_after"] = True
    return out


# ---------------------------------------------------------------- SDP ⇄ descriptors

ENCODING_TO_CODEC = {v.lower(): k for k, v in B.CODEC_ENCODING.items()}


def sip_sdp_to_descriptors(sdp_text: str) -> dict:
    """A trunk's SDP → DSIP media descriptors (what the DSIP leg re-offers). Unknown encodings are dropped;
    a section with no known codec is omitted; `inactive`/`sendonly` from a hold survive as directions."""
    sdp = B.parse_sdp(sdp_text)
    if sdp is None:
        return {"error": "unparseable"}
    media = []
    for sec in sdp.sections:
        if sec.port == 0 or sec.kind not in ("audio", "video"):
            continue
        codecs = []
        for v in sec.values("rtpmap"):
            parts = v.split(" ", 1)
            if len(parts) == 2:
                enc = parts[1].split("/")[0].lower()
                cid = ENCODING_TO_CODEC.get(enc)
                if cid and cid not in codecs:
                    codecs.append(cid)
        if not codecs:
            continue
        media.append({"type": sec.kind, "direction": sec.direction(sdp.session_direction() or "sendrecv"),
                      "codecs": [{"id": c} for c in codecs]})
    srtp = "sdes" if any(s.has("crypto") for s in sdp.sections) else ("dtls" if any("TLS" in s.protocol for s in sdp.sections) else "none")
    return {"media": media, "srtp": srtp}


def descriptors_to_sip_sdp(media: list[dict]) -> dict:
    """DSIP descriptors (the selection the DSIP side made) → what the SIP leg's m= lines must offer/answer."""
    lines = []
    for d in media:
        encs = [B.CODEC_ENCODING[c["id"]] for c in d.get("codecs", []) if c.get("id") in B.CODEC_ENCODING]
        if not encs:
            continue
        lines.append({"kind": d["type"], "encodings": encs, "direction": d.get("direction", "sendrecv")})
    return {"m_lines": lines}


# ---------------------------------------------------------------- claims and trust basis

def tel_claim(from_tn: str, identity: dict | None, *, cnam: str | None = None, gateway: str = GATEWAY_DID) -> dict:
    """PSTN caller → the `identity.claims[]` entry the gateway puts on the DSIP invite, plus the §18.1
    basis string a client renders. The caller is a claim by the gateway — never a DSIP identity."""
    attestation, verified = "none", False
    if identity:
        attestation = identity.get("attest") or "none"
        verified = bool(identity.get("verified")) and attestation != "none"
        if identity.get("orig_tn") and identity.get("orig_tn") != from_tn:
            # PASSporT orig does not match From: the attestation is about a different number.
            attestation, verified = "none", False
    claim = {"type": "tel", "number": from_tn, "attestation": attestation, "verified": verified, "verifier": gateway}
    if cnam:
        claim["cnam"] = cnam
    basis = f"Gateway attested by {gateway.removeprefix('did:web:')}"
    if verified:
        basis += f" · STIR attestation {attestation} (verified)"
    elif attestation != "none":
        basis += f" · STIR attestation {attestation} (unverified)"
    else:
        basis += " · no attestation"
    return {"claim": claim, "trust_basis": basis}


# ---------------------------------------------------------------- §6.3 downgrade rule

def downgrade(facts: dict) -> dict:
    """Which crossings emit `gateway.downgraded`. Each lost guarantee is named; the session continues."""
    lost = []
    if not facts.get("trunk_srtp", False):
        lost.append("no-srtp-on-trunk")
    if facts.get("direction") == "outbound" and not facts.get("identity_assertable", False):
        lost.append("identity-not-assertable")
    if facts.get("direction") == "inbound" and facts.get("attestation", "none") == "none":
        lost.append("no-attestation")
    if facts.get("policy_present", False):
        lost.append("policy-unenforceable")
    return {"downgraded": bool(lost), "lost": lost}


# ---------------------------------------------------------------- controller traces

class GatewayCall:
    """Minimal B2BUA controller for one call (plan §5). Events: `{"dsip": MSG}`, `{"sip": {...}}`,
    `{"timer": "C"}`. Emissions name what each leg is told; the DSIP side speaks the §12 engine's local
    event vocabulary, the SIP side speaks requests/responses."""

    def __init__(self, ctx: dict):
        self.direction = ctx.get("direction", "outbound")
        self.early_media = ctx.get("early_media", "auto")   # auto | always | never
        self.dsip = "idle"     # outbound: inviting → proceeding → active → ended; inbound: offered → alerting → active → ended
        self.sip = "idle"      # calling → early → confirmed → terminated
        self.answered = False
        self.cancelled = False

    def step(self, ev: dict) -> list[dict]:
        out: list[dict] = []
        if "dsip" in ev:
            m = ev["dsip"]; t = m.get("type")
            if t == "invite" and self.direction == "outbound":
                self.dsip, self.sip = "inviting", "calling"
                out.append({"sip": "INVITE"})
            elif t == "cancel" and self.direction == "outbound":
                self.cancelled = True
                if self.sip in ("calling", "early"):
                    out.append({"sip": "CANCEL"})
                self.dsip = "ended"
            elif t == "progress" and self.direction == "inbound":
                self.dsip = "alerting"
                out.append({"sip": {"response": 180}})
            elif t == "answer" and self.direction == "inbound":
                self.dsip, self.sip, self.answered = "active", "confirmed", True
                direction = "sendonly" if m.get("answered_by") == "screening" else "sendrecv"
                out.append({"sip": {"response": 200, "direction": direction}})
                out.append({"media": "bridge"})
            elif t == "reject" and self.direction == "inbound":
                r = map_outbound(m.get("reason", "session.failed"))
                self.dsip, self.sip = "ended", "terminated"
                out.append({"sip": {"response": r["status"], "q850": r.get("q850"), "reason_header": r["reason_header"]}})
            elif t == "update":
                direction = m.get("direction", "sendrecv")
                out.append({"sip": {"request": "re-INVITE", "direction": direction}})
            elif t == "bye":
                self.dsip = "ended"
                if self.sip in ("calling", "early", "confirmed"):
                    r = map_outbound(m.get("reason", "user.hangup"), phase="active")
                    out.append({"sip": {"request": "BYE", "q850": r["q850"], "reason_header": r["reason_header"]}})
                    self.sip = "terminated"
                out.append({"media": "release"})
            else:
                out.append({"ignore": f"dsip {t} in {self.dsip}"})
        elif "sip" in ev:
            s = ev["sip"]
            if "status" in s and self.direction == "outbound":
                st = s["status"]
                if self.cancelled:
                    if 200 <= st < 300:
                        # §12.5 rule 3 on the SIP leg: the answer crossed our CANCEL — ACK and tear down.
                        out += [{"sip": "ACK"}, {"sip": {"request": "BYE", "q850": 16, "reason_header": {"protocol": "DSIP", "text": "session.cancelled"}}}]
                    self.sip = "terminated"
                elif 100 <= st < 200:
                    if st >= 180:
                        self.sip = "early"
                        if self.dsip == "inviting":
                            self.dsip = "proceeding"
                            out.append({"dsip": {"local": "alert"}})
                    if s.get("sdp") and st == 183 and not self.answered:
                        classified = s.get("announcement")
                        if classified:
                            # App. C: an announcement the gateway can classify becomes a reason, not audio.
                            pass
                        elif self.early_media in ("auto", "always"):
                            self.answered, self.dsip = True, "active"
                            out.append({"dsip": {"local": "accept", "answered_by": "gateway"}})
                            out.append({"media": "bridge"})
                elif 200 <= st < 300:
                    self.sip = "confirmed"
                    out.append({"sip": "ACK"})
                    if not self.answered:
                        self.answered, self.dsip = True, "active"
                        out.append({"dsip": {"local": "accept", "answered_by": "gateway"}})
                        out.append({"media": "bridge"})
                elif st >= 300:
                    self.sip = "terminated"
                    if self.dsip != "ended":
                        r = map_inbound(st, s.get("q850"), phase="active" if self.answered else "pre-answer", moved_to=s.get("moved_to"))
                        self.dsip = "ended"
                        if r["carry"] == "reject":
                            out.append({"dsip": {"local": "auto_reject", "reason": r["reason"], **({"detail": r["detail"]} if "detail" in r else {})}})
                        else:
                            out.append({"dsip": {"local": "hangup", "reason": r["reason"]}})
                            out.append({"media": "release"})
            elif s.get("request") == "INVITE" and self.direction == "inbound":
                self.dsip, self.sip = "offered", "early"
                tc = tel_claim(s.get("from_tn", ""), s.get("identity"), cnam=s.get("cnam"))
                out.append({"dsip": {"local": "place_call", "claims": [tc["claim"]], "trust_basis": tc["trust_basis"]}})
                out.append({"sip": {"response": 100}})
            elif s.get("request") == "CANCEL" and self.direction == "inbound":
                self.sip = "terminated"
                out.append({"sip": {"response": 200}})
                if self.dsip in ("offered", "alerting"):
                    self.dsip = "ended"
                    out += [{"dsip": {"local": "cancel"}}, {"sip": {"response": 487}}]
            elif s.get("request") == "ACK":
                pass
            elif s.get("request") == "BYE":
                self.sip = "terminated"
                out.append({"sip": {"response": 200}})
                if self.dsip != "ended":
                    r = map_inbound(None, s.get("q850"), phase="active")
                    self.dsip = "ended"
                    out += [{"dsip": {"local": "hangup", "reason": r["reason"]}}, {"media": "release"}]
            elif s.get("request") == "REFER":
                out.append({"sip": {"response": 603}})   # round one: no transfer
            elif s.get("request") == "re-INVITE":
                direction = s.get("direction", "sendrecv")
                out.append({"dsip": {"local": "update", "direction": direction}})
            else:
                out.append({"ignore": f"sip {s}"})
        elif ev.get("timer") == "C":
            if self.sip in ("calling", "early") and not self.answered:
                self.sip, self.dsip = "terminated", "ended"
                out += [{"sip": "CANCEL"}, {"dsip": {"local": "auto_reject", "reason": "gateway.unreachable", "detail": "SIP Timer C"}}]
        return out

    def snapshot(self) -> dict:
        return {"dsip": self.dsip, "sip": self.sip}


def run(v: dict) -> Any:
    inp, ctx = v["input"], v.get("context", {})
    check = inp["check"]
    if check == "reason-inbound":
        return map_inbound(inp.get("sip_status"), inp.get("q850"), phase=inp.get("phase", "pre-answer"), moved_to=inp.get("moved_to"))
    if check == "reason-outbound":
        return map_outbound(inp["reason"], phase=inp.get("phase", "pre-answer"))
    if check == "sdp-to-descriptors":
        return sip_sdp_to_descriptors(inp["sdp"])
    if check == "descriptors-to-sdp":
        return descriptors_to_sip_sdp(inp["media"])
    if check == "claims":
        return tel_claim(inp["from_tn"], inp.get("identity"), cnam=inp.get("cnam"))
    if check == "downgrade":
        return downgrade(inp["facts"])
    if check == "trace":
        call = GatewayCall(ctx)
        steps = []
        for st in inp["steps"]:
            steps.append({"emit": call.step(st["event"]), "state": call.snapshot()})
        return {"steps": steps}
    raise ValueError(f"unknown gateway check {check}")
