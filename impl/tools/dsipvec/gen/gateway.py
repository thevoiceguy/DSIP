"""`gateway/` vectors — Phase 4 G0: reason mapping both ways (§15.5), SDP ⇄ descriptors, PSTN
caller claims (§18.1), the §6.3 downgrade rule, and B2BUA controller traces (plan §5)."""
from __future__ import annotations

from .common import vector, accept, reject
from .binding import sdp as webrtc_sdp

GW = "did:web:gw.example"


def gv(vid, desc, refs, inp, expect, ctx=None):
    return vector(f"gateway/{vid}", "gateway", desc, refs, ctx or {}, inp, expect)


def trace(vid, desc, refs, steps, ctx):
    return gv(vid, desc, refs, {"check": "trace", "steps": [{"event": e} for e, _, _ in steps]},
              {"steps": [{"emit": em, "state": st} for _, em, st in steps]}, ctx=ctx)


def sip_sdp(encs=("PCMU", "opus"), direction="sendrecv", crypto=False, proto="RTP/AVP"):
    pts = {"PCMU": "0 PCMU/8000", "PCMA": "8 PCMA/8000", "G722": "9 G722/8000", "opus": "111 opus/48000/2", "GSM": "3 GSM/8000"}
    lines = ["v=0", "o=trunk 1 1 IN IP4 198.51.100.5", "s=-", "c=IN IP4 198.51.100.5", "t=0 0",
             "m=audio 20000 " + proto + " " + " ".join(pts[e].split(" ")[0] for e in encs)]
    lines += [f"a=rtpmap:{pts[e]}" for e in encs]
    if crypto:
        lines.append("a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnUnCg==")
    lines.append(f"a={direction}")
    return "\r\n".join(lines) + "\r\n"


def vectors() -> list[dict]:
    out = []
    DSIP_HDR = lambda t: {"protocol": "DSIP", "text": t}
    # ---- §15.5 inbound
    for vid, st, q, phase, exp in [
        ("inbound-486-busy", 486, None, "pre-answer", {"reason": "endpoint.busy", "carry": "reject", "detail": "SIP 486"}),
        ("inbound-480-unavailable", 480, None, "pre-answer", {"reason": "endpoint.unavailable", "carry": "reject", "detail": "SIP 480"}),
        ("inbound-603-declined", 603, None, "pre-answer", {"reason": "user.declined", "carry": "reject", "detail": "SIP 603"}),
        ("inbound-404-unknown", 404, None, "pre-answer", {"reason": "identity.unknown", "carry": "reject", "detail": "SIP 404"}),
        ("inbound-410-not-in-service", 410, None, "pre-answer", {"reason": "identity.not-in-service", "carry": "reject", "detail": "SIP 410"}),
        ("inbound-488-media", 488, None, "pre-answer", {"reason": "media.unsupported", "carry": "reject", "detail": "SIP 488"}),
        ("inbound-503-unreachable", 503, None, "pre-answer", {"reason": "gateway.unreachable", "carry": "reject", "detail": "SIP 503"}),
        ("inbound-487-cancelled", 487, None, "pre-answer", {"reason": "session.cancelled", "carry": "reject", "detail": "SIP 487"}),
        ("inbound-q850-precedence", 480, 17, "pre-answer", {"reason": "endpoint.busy", "carry": "reject", "detail": "Q.850 17"}),
        ("inbound-unmappable-500", 500, None, "pre-answer", {"reason": "gateway.mapped", "carry": "reject", "detail": "SIP 500"}),
        ("inbound-unmappable-q850", None, 99, "pre-answer", {"reason": "gateway.mapped", "carry": "reject", "detail": "Q.850 99"}),
        ("inbound-bye-no-reason", None, None, "active", {"reason": "user.hangup", "carry": "bye"}),
        ("inbound-bye-q850-16", None, 16, "active", {"reason": "user.hangup", "carry": "bye", "detail": "Q.850 16"}),
        ("inbound-bye-q850-41-unreachable", None, 41, "active", {"reason": "gateway.unreachable", "carry": "bye", "detail": "Q.850 41"}),
        ("inbound-active-attempt-token-becomes-mapped", None, 17, "active", {"reason": "gateway.mapped", "carry": "bye", "detail": "Q.850 17"}),
        ("inbound-transport-503-error", 503, None, "transport", {"reason": "gateway.unreachable", "carry": "error", "detail": "SIP 503"}),
    ]:
        inp = {"check": "reason-inbound", "phase": phase}
        if st is not None:
            inp["sip_status"] = st
        if q is not None:
            inp["q850"] = q
        out.append(gv(vid, f"SIP {st} / Q.850 {q} in phase {phase} → {exp['reason']} on {exp['carry']}.", ["§15.5"], inp, exp))
    out.append(gv("inbound-410-with-redirect-is-moved", "410 with a known successor maps to identity.moved with the target in detail.", ["§15.5", "§15.4"],
                  {"check": "reason-inbound", "sip_status": 410, "moved_to": "tel:+15557654321"},
                  {"reason": "identity.moved", "carry": "reject", "detail": "tel:+15557654321"}))
    # ---- §15.5 outbound
    for vid, tok, phase, exp in [
        ("outbound-user-declined-603", "user.declined", "pre-answer", {"status": 603, "q850": 21, "reason_header": DSIP_HDR("user.declined")}),
        ("outbound-endpoint-busy-486", "endpoint.busy", "pre-answer", {"status": 486, "q850": 17, "reason_header": DSIP_HDR("endpoint.busy")}),
        ("outbound-policy-blocked-403", "policy.blocked", "pre-answer", {"status": 403, "q850": 21, "reason_header": DSIP_HDR("policy.blocked")}),
        ("outbound-first-contact-403", "policy.first-contact-required", "pre-answer", {"status": 403, "q850": 21, "reason_header": DSIP_HDR("policy.first-contact-required")}),
        ("outbound-media-unsupported-488", "media.unsupported", "pre-answer", {"status": 488, "q850": 65, "reason_header": DSIP_HDR("media.unsupported")}),
        ("outbound-rate-limited-503-retry-after", "policy.rate-limited", "pre-answer", {"status": 503, "q850": 42, "reason_header": DSIP_HDR("policy.rate-limited"), "retry_after": True}),
        ("outbound-unknown-token-category-fallback", "user.stepped-out", "pre-answer", {"status": 603, "q850": 21, "reason_header": DSIP_HDR("user.stepped-out")}),
        ("outbound-unknown-category-500", "x-cc.queue-full", "pre-answer", {"status": 500, "q850": 41, "reason_header": DSIP_HDR("x-cc.queue-full")}),
        ("outbound-bye-hangup", "user.hangup", "active", {"method": "BYE", "q850": 16, "reason_header": DSIP_HDR("user.hangup")}),
        ("outbound-bye-media-failed", "media.failed", "active", {"method": "BYE", "q850": 47, "reason_header": DSIP_HDR("media.failed")}),
        ("outbound-bye-policy-terminated", "policy.terminated", "active", {"method": "BYE", "q850": 31, "reason_header": DSIP_HDR("policy.terminated")}),
    ]:
        out.append(gv(vid, f"DSIP {tok} in phase {phase} → SIP {exp.get('status') or exp.get('method')} with Reason DSIP + Q.850.", ["§15.5", "§15.1"],
                      {"check": "reason-outbound", "reason": tok, "phase": phase}, exp))
    # ---- SDP ⇄ descriptors
    out.append(gv("sdp-trunk-g711-opus-to-descriptors", "A trunk offering PCMU+opus, plain RTP → two codec ids, srtp none.", ["§16.2", "§17.2"],
                  {"check": "sdp-to-descriptors", "sdp": sip_sdp(("PCMU", "opus"))},
                  {"media": [{"type": "audio", "direction": "sendrecv", "codecs": [{"id": "codec:audio/pcmu"}, {"id": "codec:audio/opus"}]}], "srtp": "none"}))
    out.append(gv("sdp-trunk-sdes-hold", "SDES-protected trunk on hold (sendonly): direction survives, srtp sdes.", ["§16.2"],
                  {"check": "sdp-to-descriptors", "sdp": sip_sdp(("PCMA",), direction="sendonly", crypto=True, proto="RTP/SAVP")},
                  {"media": [{"type": "audio", "direction": "sendonly", "codecs": [{"id": "codec:audio/pcma"}]}], "srtp": "sdes"}))
    out.append(gv("sdp-trunk-unknown-codec-dropped", "An encoding DSIP has no id for (GSM) is dropped; a section with nothing known is omitted.", ["§16.2"],
                  {"check": "sdp-to-descriptors", "sdp": sip_sdp(("GSM",))}, {"media": [], "srtp": "none"}))
    out.append(gv("sdp-trunk-unparseable", "Not SDP.", ["§16.2"], {"check": "sdp-to-descriptors", "sdp": "hello"}, {"error": "unparseable"}))
    out.append(gv("descriptors-to-trunk-sdp", "The DSIP selection → the SIP leg's m= line (encodings, direction).", ["§16.2", "§14.2"],
                  {"check": "descriptors-to-sdp", "media": [{"type": "audio", "direction": "recvonly", "codecs": [{"id": "codec:audio/opus"}, {"id": "codec:audio/g722"}]}]},
                  {"m_lines": [{"kind": "audio", "encodings": ["opus", "G722"], "direction": "recvonly"}]}))
    # ---- claims (§18.1, §6.3)
    out.append(gv("claims-attestation-a-verified", "Verified PASSporT with attestation A → verified tel claim; basis names the gateway and the level.", ["§18.1", "§6.3"],
                  {"check": "claims", "from_tn": "+15551234567", "identity": {"attest": "A", "verified": True, "orig_tn": "+15551234567"}, "cnam": "ACME Corp"},
                  {"claim": {"type": "tel", "number": "+15551234567", "attestation": "A", "verified": True, "verifier": GW, "cnam": "ACME Corp"},
                   "trust_basis": "Gateway attested by gw.example · STIR attestation A (verified)"}))
    out.append(gv("claims-no-identity-header", "No Identity header: attestation none, never a badge.", ["§18.1"],
                  {"check": "claims", "from_tn": "+15551234567"},
                  {"claim": {"type": "tel", "number": "+15551234567", "attestation": "none", "verified": False, "verifier": GW},
                   "trust_basis": "Gateway attested by gw.example · no attestation"}))
    out.append(gv("claims-signature-failed", "PASSporT present but verification failed: level shown as unverified.", ["§18.1", "§20.4"],
                  {"check": "claims", "from_tn": "+15551234567", "identity": {"attest": "B", "verified": False, "orig_tn": "+15551234567"}},
                  {"claim": {"type": "tel", "number": "+15551234567", "attestation": "B", "verified": False, "verifier": GW},
                   "trust_basis": "Gateway attested by gw.example · STIR attestation B (unverified)"}))
    out.append(gv("claims-orig-mismatch", "PASSporT orig differs from From: the attestation is about another number and is discarded.", ["§18.1", "§20.4"],
                  {"check": "claims", "from_tn": "+15551234567", "identity": {"attest": "A", "verified": True, "orig_tn": "+15559999999"}},
                  {"claim": {"type": "tel", "number": "+15551234567", "attestation": "none", "verified": False, "verifier": GW},
                   "trust_basis": "Gateway attested by gw.example · no attestation"}))
    # ---- downgrade (§6.3)
    out.append(gv("downgrade-outbound-plain-trunk", "Outbound over a plain-RTP trunk with no identity assertion and a policy block: three losses.", ["§6.3", "§15.4", "§16.4"],
                  {"check": "downgrade", "facts": {"direction": "outbound", "trunk_srtp": False, "identity_assertable": False, "policy_present": True}},
                  {"downgraded": True, "lost": ["no-srtp-on-trunk", "identity-not-assertable", "policy-unenforceable"]}))
    out.append(gv("downgrade-outbound-asserted-srtp", "Outbound over SRTP with a signed PASSporT and no policy: no downgrade.", ["§6.3"],
                  {"check": "downgrade", "facts": {"direction": "outbound", "trunk_srtp": True, "identity_assertable": True, "policy_present": False}},
                  {"downgraded": False, "lost": []}))
    out.append(gv("downgrade-inbound-no-attestation", "Inbound with SRTP but no attestation: one loss.", ["§6.3", "§18.1"],
                  {"check": "downgrade", "facts": {"direction": "inbound", "trunk_srtp": True, "attestation": "none"}},
                  {"downgraded": True, "lost": ["no-attestation"]}))
    # ---- controller traces (plan §5)
    CALLING, EARLY, CONF, TERM = "calling", "early", "confirmed", "terminated"
    st = lambda d, s: {"dsip": d, "sip": s}
    out.append(trace("trace-outbound-ring-answer-hangup", "DSIP→PSTN: INVITE, 180 → ringing, 200 → answered_by gateway + ACK + bridge, DSIP bye → BYE.", ["§15.5", "§14.1", "§12.4"], [
        ({"dsip": {"type": "invite"}}, [{"sip": "INVITE"}], st("inviting", CALLING)),
        ({"sip": {"status": 100}}, [], st("inviting", CALLING)),
        ({"sip": {"status": 180}}, [{"dsip": {"local": "alert"}}], st("proceeding", EARLY)),
        ({"sip": {"status": 200, "sdp": True}}, [{"sip": "ACK"}, {"dsip": {"local": "accept", "answered_by": "gateway"}}, {"media": "bridge"}], st("active", CONF)),
        ({"dsip": {"type": "bye", "reason": "user.hangup"}}, [{"sip": {"request": "BYE", "q850": 16, "reason_header": DSIP_HDR("user.hangup")}}, {"media": "release"}], st("ended", TERM)),
    ], ctx={"direction": "outbound"}))
    out.append(trace("trace-outbound-early-media", "183 with SDP under early_media auto: the DSIP leg is answered by the gateway and audio passes; 200 later only ACKs.", ["§15.5", "Appendix C"], [
        ({"dsip": {"type": "invite"}}, [{"sip": "INVITE"}], st("inviting", CALLING)),
        ({"sip": {"status": 183, "sdp": True}}, [{"dsip": {"local": "alert"}}, {"dsip": {"local": "accept", "answered_by": "gateway"}}, {"media": "bridge"}], st("active", EARLY)),
        ({"sip": {"status": 200, "sdp": True}}, [{"sip": "ACK"}], st("active", CONF)),
    ], ctx={"direction": "outbound", "early_media": "auto"}))
    out.append(trace("trace-outbound-early-media-never", "early_media never: 183 only rings; 200 answers.", ["Appendix C"], [
        ({"dsip": {"type": "invite"}}, [{"sip": "INVITE"}], st("inviting", CALLING)),
        ({"sip": {"status": 183, "sdp": True}}, [{"dsip": {"local": "alert"}}], st("proceeding", EARLY)),
        ({"sip": {"status": 200, "sdp": True}}, [{"sip": "ACK"}, {"dsip": {"local": "accept", "answered_by": "gateway"}}, {"media": "bridge"}], st("active", CONF)),
    ], ctx={"direction": "outbound", "early_media": "never"}))
    out.append(trace("trace-outbound-486", "486 before answer → reject endpoint.busy on the DSIP leg.", ["§15.5"], [
        ({"dsip": {"type": "invite"}}, [{"sip": "INVITE"}], st("inviting", CALLING)),
        ({"sip": {"status": 486}}, [{"dsip": {"local": "auto_reject", "reason": "endpoint.busy", "detail": "SIP 486"}}], st("ended", TERM)),
    ], ctx={"direction": "outbound"}))
    out.append(trace("trace-outbound-cancel-487", "DSIP cancel → CANCEL; 487 closes the SIP leg with nothing more to tell the DSIP side.", ["§12.5", "§15.5"], [
        ({"dsip": {"type": "invite"}}, [{"sip": "INVITE"}], st("inviting", CALLING)),
        ({"sip": {"status": 180}}, [{"dsip": {"local": "alert"}}], st("proceeding", EARLY)),
        ({"dsip": {"type": "cancel"}}, [{"sip": "CANCEL"}], st("ended", EARLY)),
        ({"sip": {"status": 487}}, [], st("ended", TERM)),
    ], ctx={"direction": "outbound"}))
    out.append(trace("trace-outbound-cancel-crosses-200", "A 200 OK crossing our CANCEL is ACKed and torn down with BYE session.cancelled (§12.5 rule 3 on the SIP leg).", ["§12.5"], [
        ({"dsip": {"type": "invite"}}, [{"sip": "INVITE"}], st("inviting", CALLING)),
        ({"dsip": {"type": "cancel"}}, [{"sip": "CANCEL"}], st("ended", CALLING)),
        ({"sip": {"status": 200, "sdp": True}}, [{"sip": "ACK"}, {"sip": {"request": "BYE", "q850": 16, "reason_header": DSIP_HDR("session.cancelled")}}], st("ended", TERM)),
    ], ctx={"direction": "outbound"}))
    out.append(trace("trace-outbound-timer-c", "No final response: SIP Timer C → CANCEL and reject gateway.unreachable.", ["§15.5", "§12.9"], [
        ({"dsip": {"type": "invite"}}, [{"sip": "INVITE"}], st("inviting", CALLING)),
        ({"timer": "C"}, [{"sip": "CANCEL"}, {"dsip": {"local": "auto_reject", "reason": "gateway.unreachable", "detail": "SIP Timer C"}}], st("ended", TERM)),
    ], ctx={"direction": "outbound"}))
    out.append(trace("trace-outbound-remote-bye", "PSTN side hangs up with Q.850 16 → DSIP bye user.hangup.", ["§15.5"], [
        ({"dsip": {"type": "invite"}}, [{"sip": "INVITE"}], st("inviting", CALLING)),
        ({"sip": {"status": 200, "sdp": True}}, [{"sip": "ACK"}, {"dsip": {"local": "accept", "answered_by": "gateway"}}, {"media": "bridge"}], st("active", CONF)),
        ({"sip": {"request": "BYE", "q850": 16}}, [{"sip": {"response": 200}}, {"dsip": {"local": "hangup", "reason": "user.hangup"}}, {"media": "release"}], st("ended", TERM)),
    ], ctx={"direction": "outbound"}))
    claim_a = {"type": "tel", "number": "+15551234567", "attestation": "A", "verified": True, "verifier": GW}
    basis_a = "Gateway attested by gw.example · STIR attestation A (verified)"
    out.append(trace("trace-inbound-answered", "PSTN→DSIP: INVITE with verified attestation → DSIP invite with the tel claim; ringing → 180; user answer → 200 + bridge; BYE from PSTN.", ["§18.1", "§14.1", "§15.5"], [
        ({"sip": {"request": "INVITE", "from_tn": "+15551234567", "identity": {"attest": "A", "verified": True, "orig_tn": "+15551234567"}}},
         [{"dsip": {"local": "place_call", "claims": [claim_a], "trust_basis": basis_a}}, {"sip": {"response": 100}}], st("offered", EARLY)),
        ({"dsip": {"type": "progress", "status": "ringing"}}, [{"sip": {"response": 180}}], st("alerting", EARLY)),
        ({"dsip": {"type": "answer", "answered_by": "user"}}, [{"sip": {"response": 200, "direction": "sendrecv"}}, {"media": "bridge"}], st("active", CONF)),
        ({"sip": {"request": "ACK"}}, [], st("active", CONF)),
        ({"sip": {"request": "BYE"}}, [{"sip": {"response": 200}}, {"dsip": {"local": "hangup", "reason": "user.hangup"}}, {"media": "release"}], st("ended", TERM)),
    ], ctx={"direction": "inbound"}))
    out.append(trace("trace-inbound-screened-then-escalated", "A screening answer makes the SIP leg sendonly toward the PSTN (caller heard, nothing played back); escalation re-INVITEs sendrecv.", ["§14.4", "§12.8"], [
        ({"sip": {"request": "INVITE", "from_tn": "+15551234567"}},
         [{"dsip": {"local": "place_call", "claims": [{"type": "tel", "number": "+15551234567", "attestation": "none", "verified": False, "verifier": GW}],
                    "trust_basis": "Gateway attested by gw.example · no attestation"}}, {"sip": {"response": 100}}], st("offered", EARLY)),
        ({"dsip": {"type": "answer", "answered_by": "screening"}}, [{"sip": {"response": 200, "direction": "sendonly"}}, {"media": "bridge"}], st("active", CONF)),
        ({"dsip": {"type": "update", "direction": "sendrecv"}}, [{"sip": {"request": "re-INVITE", "direction": "sendrecv"}}], st("active", CONF)),
    ], ctx={"direction": "inbound"}))
    out.append(trace("trace-inbound-declined-and-first-contact", "DSIP reject user.declined → 603; a first-contact refusal → 403 with the DSIP token in Reason.", ["§15.5", "§19.4"], [
        ({"sip": {"request": "INVITE", "from_tn": "+15551234567"}},
         [{"dsip": {"local": "place_call", "claims": [{"type": "tel", "number": "+15551234567", "attestation": "none", "verified": False, "verifier": GW}],
                    "trust_basis": "Gateway attested by gw.example · no attestation"}}, {"sip": {"response": 100}}], st("offered", EARLY)),
        ({"dsip": {"type": "reject", "reason": "policy.first-contact-required"}},
         [{"sip": {"response": 403, "q850": 21, "reason_header": DSIP_HDR("policy.first-contact-required")}}], st("ended", TERM)),
    ], ctx={"direction": "inbound"}))
    out.append(trace("trace-inbound-cancel", "PSTN caller hangs up while ringing: CANCEL → 200 + DSIP cancel + 487.", ["§12.5", "§12.11"], [
        ({"sip": {"request": "INVITE", "from_tn": "+15551234567"}},
         [{"dsip": {"local": "place_call", "claims": [{"type": "tel", "number": "+15551234567", "attestation": "none", "verified": False, "verifier": GW}],
                    "trust_basis": "Gateway attested by gw.example · no attestation"}}, {"sip": {"response": 100}}], st("offered", EARLY)),
        ({"dsip": {"type": "progress", "status": "ringing"}}, [{"sip": {"response": 180}}], st("alerting", EARLY)),
        ({"sip": {"request": "CANCEL"}}, [{"sip": {"response": 200}}, {"dsip": {"local": "cancel"}}, {"sip": {"response": 487}}], st("ended", TERM)),
    ], ctx={"direction": "inbound"}))
    out.append(trace("trace-inbound-refer-and-hold", "REFER is declined in round one; a hold re-INVITE becomes a DSIP update with the mirrored direction.", ["§12.8"], [
        ({"sip": {"request": "INVITE", "from_tn": "+15551234567"}},
         [{"dsip": {"local": "place_call", "claims": [{"type": "tel", "number": "+15551234567", "attestation": "none", "verified": False, "verifier": GW}],
                    "trust_basis": "Gateway attested by gw.example · no attestation"}}, {"sip": {"response": 100}}], st("offered", EARLY)),
        ({"dsip": {"type": "answer", "answered_by": "user"}}, [{"sip": {"response": 200, "direction": "sendrecv"}}, {"media": "bridge"}], st("active", CONF)),
        ({"sip": {"request": "REFER"}}, [{"sip": {"response": 603}}], st("active", CONF)),
        ({"sip": {"request": "re-INVITE", "direction": "sendonly"}}, [{"dsip": {"local": "update", "direction": "sendonly"}}], st("active", CONF)),
    ], ctx={"direction": "inbound"}))
    return out
