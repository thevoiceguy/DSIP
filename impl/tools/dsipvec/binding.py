"""WebRTC Media Binding 1.0 (v0.7 companion) — reference semantics for the `media-binding` vectors.

Spec: B§2 (descriptor and SDP; authority rule B§2.1; SDP profile B§2.2), B§3 (roles, DTLS role
from a=setup, codec mapping), B§4 (candidate exchange: carriage, timing/buffering, attribution),
B§5 (renegotiation on the same transport; ICE restart unsupported), B§6.1 (one answer per offer).

Everything here is pure: an SDP mini-parser plus stateless checks and two tiny state machines.
`B§` distinguishes binding sections from Core `§` sections in citations and coverage.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .verdict import Verdict

# B§3.4 — DSIP codec identifiers → SDP encoding names (case-insensitive on the wire).
CODEC_ENCODING = {
    "codec:audio/opus": "opus", "codec:audio/pcmu": "PCMU", "codec:audio/pcma": "PCMA", "codec:audio/g722": "G722",
    "codec:video/h264": "H264", "codec:video/vp8": "VP8", "codec:video/vp9": "VP9", "codec:video/av1": "AV1",
}
DIRECTIONS = ("sendrecv", "sendonly", "recvonly", "inactive")
SECURE_PROTOCOLS = ("UDP/TLS/RTP/SAVPF", "UDP/TLS/RTP/SAVP", "TCP/TLS/RTP/SAVPF", "RTP/SAVPF", "RTP/SAVP")


@dataclass
class Section:
    kind: str
    port: int
    protocol: str
    formats: list[str]
    attrs: list[tuple[str, str | None]] = field(default_factory=list)

    def values(self, name: str) -> list[str]:
        return [v for n, v in self.attrs if n == name and v is not None]

    def has(self, name: str) -> bool:
        return any(n == name for n, _ in self.attrs)

    def direction(self, default: str | None) -> str | None:
        for n, v in self.attrs:
            if n in DIRECTIONS and v is None:
                return n
        return default

    def encodings(self) -> set[str]:
        out = set()
        for v in self.values("rtpmap"):
            parts = v.split(" ", 1)
            if len(parts) == 2:
                out.add(parts[1].split("/")[0].lower())
        return out


@dataclass
class Sdp:
    session_attrs: list[tuple[str, str | None]]
    sections: list[Section]

    def session_value(self, name: str) -> str | None:
        for n, v in self.session_attrs:
            if n == name:
                return v
        return None

    def session_direction(self) -> str | None:
        for n, v in self.session_attrs:
            if n in DIRECTIONS and v is None:
                return n
        return None


def parse_sdp(text: str) -> Sdp | None:
    """Minimal, tolerant SDP parse: `m=` sections and `a=` attributes; everything else ignored."""
    if not isinstance(text, str) or not text.startswith("v=0"):
        return None
    session_attrs: list[tuple[str, str | None]] = []
    sections: list[Section] = []
    for raw in text.replace("\r\n", "\n").split("\n"):
        line = raw.strip()
        if len(line) < 2 or line[1] != "=":
            continue
        key, val = line[0], line[2:]
        if key == "m":
            parts = val.split()
            if len(parts) < 3:
                return None
            try:
                port = int(parts[1].split("/")[0])
            except ValueError:
                return None
            sections.append(Section(parts[0], port, parts[2], parts[3:]))
        elif key == "a":
            name, _, value = val.partition(":")
            attr = (name, value if _ else None)
            (sections[-1].attrs if sections else session_attrs).append(attr)
    return Sdp(session_attrs, sections)


def _attr(sdp: Sdp, sec: Section, name: str) -> str | None:
    vals = sec.values(name)
    return vals[0] if vals else sdp.session_value(name)


def _reject(code: str, reason: str, detail: str) -> Verdict:
    return Verdict.reject(code, reason, detail=detail)


def check_description(payload: dict, *, is_answer: bool, offer_sdp: Sdp | None = None) -> Verdict:
    """B§2.1/B§2.2/B§3.3: the descriptor and its SDP must agree; the SDP must carry the profile.

    Offers fail with `media.unsupported` (or `media.offer-required` without SDP); answers fail
    with `media.failed` (the accepted leg is torn down with `bye`)."""
    bad = "media.failed" if is_answer else "media.unsupported"
    transports = payload.get("transports") or []
    t = transports[0] if transports else {}
    if t.get("id") != "transport:webrtc":
        return Verdict.accept(binding="not-webrtc")
    if not is_answer and t.get("ice") != "trickle":
        return _reject("binding-ice-mode", bad, f"ice={t.get('ice')!r}")
    if is_answer and "ice" in t and t["ice"] != "trickle":
        return _reject("binding-ice-mode", bad, f"ice={t.get('ice')!r}")
    sdp_text = t.get("sdp")
    if not isinstance(sdp_text, str) or not sdp_text:
        return _reject("binding-sdp-missing", "media.failed" if is_answer else "media.offer-required", "transports[0].sdp")
    sdp = parse_sdp(sdp_text)
    if sdp is None:
        return _reject("binding-sdp-invalid", bad, "unparseable SDP")
    media = payload.get("media") or []
    # Answers mirror the offer's section count; rejected sections (port 0) carry no descriptor.
    live = [s for s in sdp.sections if s.port != 0]
    if is_answer and offer_sdp is not None and len(sdp.sections) != len(offer_sdp.sections):
        return _reject("binding-section-count", bad, f"{len(sdp.sections)} sections for an offer of {len(offer_sdp.sections)}")
    if any(s.kind == "application" for s in live):
        return _reject("binding-extra-section", bad, "m=application is outside Core v1.0")
    if len(live) != len(media):
        return _reject("binding-section-count", bad, f"{len(live)} live m= sections for {len(media)} media descriptors")
    for i, (desc, sec) in enumerate(zip(media, live)):
        if sec.kind != desc.get("type"):
            return _reject("binding-kind-mismatch", bad, f"section {i}: m={sec.kind} for type {desc.get('type')}")
        if sec.protocol not in SECURE_PROTOCOLS:
            return _reject("binding-encryption", "media.encryption-required" if not is_answer else bad, f"section {i}: {sec.protocol}")
        direction = sec.direction(sdp.session_direction() or "sendrecv")
        if direction != desc.get("direction"):
            return _reject("binding-direction-mismatch", bad, f"section {i}: a={direction} for direction {desc.get('direction')}")
        enc = sec.encodings()
        for c in desc.get("codecs") or []:
            name = CODEC_ENCODING.get(c.get("id"))
            if name is not None and name.lower() not in enc:
                return _reject("binding-codec-missing", bad, f"section {i}: no rtpmap for {c.get('id')}")
        if not sec.has("rtcp-mux"):
            return _reject("binding-rtcp-mux-missing", bad, f"section {i}")
        fp = _attr(sdp, sec, "fingerprint")
        if fp is None or not fp.lower().startswith("sha-256 "):
            return _reject("binding-fingerprint-missing", bad, f"section {i}: a=fingerprint:sha-256 required")
        if _attr(sdp, sec, "ice-ufrag") is None or _attr(sdp, sec, "ice-pwd") is None:
            return _reject("binding-ice-credentials-missing", bad, f"section {i}")
        setup = _attr(sdp, sec, "setup")
        if is_answer:
            if setup not in ("active", "passive"):
                return _reject("binding-setup-invalid", bad, f"section {i}: answer a=setup:{setup} (must be active or passive)")
        elif setup != "actpass":
            return _reject("binding-setup-invalid", bad, f"section {i}: offer a=setup:{setup} (must be actpass)")
    return Verdict.accept()


def check_offer(payload: dict) -> Verdict:
    """B§2: an `invite`/`update` offer."""
    return check_description(payload, is_answer=False)


def check_answer(offer: dict, answer: dict) -> Verdict:
    """B§2/B§3.1: an `answer` against the offer it selects from; also the ICE-credential rule on re-answers."""
    otr = (offer.get("transports") or [{}])[0]
    osdp = parse_sdp(otr.get("sdp") or "") if isinstance(otr.get("sdp"), str) else None
    return check_description(answer, is_answer=True, offer_sdp=osdp)


def dtls_roles(offer_setup: str, answer_setup: str) -> dict:
    """B§3.3: who is the DTLS client. Offer MUST be actpass; answer MUST be active or passive."""
    if offer_setup != "actpass":
        return Verdict.reject("binding-setup-invalid", "media.unsupported", detail=f"offer a=setup:{offer_setup}").to_expect()
    if answer_setup == "active":
        return {"verdict": "accept", "offerer": "server", "answerer": "client"}
    if answer_setup == "passive":
        return {"verdict": "accept", "offerer": "client", "answerer": "server"}
    return Verdict.reject("binding-setup-invalid", "media.failed", detail=f"answer a=setup:{answer_setup}").to_expect()


def ice_credentials(payload: dict) -> tuple[str | None, str | None]:
    t = (payload.get("transports") or [{}])[0]
    sdp = parse_sdp(t.get("sdp") or "") if isinstance(t.get("sdp"), str) else None
    if sdp is None:
        return None, None
    sec = sdp.sections[0] if sdp.sections else None
    if sec is None:
        return sdp.session_value("ice-ufrag"), sdp.session_value("ice-pwd")
    return _attr(sdp, sec, "ice-ufrag"), _attr(sdp, sec, "ice-pwd")


class CandidateExchange:
    """B§4.2–B§4.4: local candidates are buffered until ACTIVE and sent in signed `info`; the
    end marker is sent exactly once per local description; remote candidates are buffered until
    the remote description is applied, applied in order, ignored after the peer's end marker or
    from any device that is not party to the session, and dropped when the session ends."""

    def __init__(self, ctx: dict):
        self.peer = ctx.get("peer")
        self.active = False
        self.remote_applied = False
        self.local_buf: list[dict] = []
        self.gathering_complete = False
        self.end_sent = False
        self.remote_buf: list[dict] = []
        self.remote_end = False
        self.ended = False

    def step(self, ev: dict) -> list[dict]:
        out: list[dict] = []
        if self.ended:
            return [{"ignore": "ended"}]
        if "local_candidate" in ev:
            if self.active:
                out.append({"send_info": {"candidates": 1, "end_of_candidates": False}})
            else:
                self.local_buf.append(ev["local_candidate"])
                out.append({"buffer": "local", "n": len(self.local_buf)})
        elif "gathering_complete" in ev:
            self.gathering_complete = True
            if self.active and not self.end_sent:
                self.end_sent = True
                out.append({"send_info": {"candidates": 0, "end_of_candidates": True}})
        elif "active" in ev:
            self.active = True
            if self.local_buf or (self.gathering_complete and not self.end_sent):
                end = self.gathering_complete and not self.end_sent
                out.append({"send_info": {"candidates": len(self.local_buf), "end_of_candidates": end}})
                self.local_buf = []
                self.end_sent = self.end_sent or end
        elif "remote_description" in ev:
            self.remote_applied = True
            if self.remote_buf:
                out.append({"apply": len(self.remote_buf)})
                self.remote_buf = []
        elif "remote_info" in ev:
            info = ev["remote_info"]
            if self.peer is not None and info.get("from") != self.peer:
                return [{"ignore": "not-party"}]
            cands = list(info.get("candidates", []))
            if self.remote_end:
                return [{"ignore": "after-end"}]
            if cands:
                if self.remote_applied:
                    out.append({"apply": len(cands)})
                else:
                    self.remote_buf.extend(cands)
                    out.append({"buffer": "remote", "n": len(self.remote_buf)})
            if info.get("end_of_candidates"):
                self.remote_end = True
                out.append({"remote_end": True})
        elif "session_end" in ev:
            self.ended = True
            if self.remote_buf or self.local_buf:
                out.append({"drop_buffered": len(self.remote_buf) + len(self.local_buf)})
                self.remote_buf, self.local_buf = [], []
        return out


class Renegotiation:
    """B§5: a re-offer is a full offer on the same transport (same ICE credentials); the sender
    keeps its current description until the answer applies and rolls back on reject; a remote
    re-offer that changes the ICE credentials is an ICE restart and is refused."""

    def __init__(self, ctx: dict):
        self.ufrag = ctx.get("ufrag")
        self.pending: str | None = None

    def step(self, ev: dict) -> list[dict]:
        if "local_reoffer" in ev:
            u = ev["local_reoffer"].get("ufrag")
            if u != self.ufrag:
                return [{"error": "binding-ice-restart", "detail": "a re-offer MUST keep the ICE credentials"}]
            self.pending = u
            return [{"local_description": "pending"}]
        if "remote_answer" in ev:
            if self.pending is None:
                return [{"ignore": "no-pending-offer"}]
            self.pending = None
            return [{"apply": "answer"}, {"local_description": "current"}]
        if "remote_reject" in ev:
            if self.pending is None:
                return [{"ignore": "no-pending-offer"}]
            self.pending = None
            return [{"rollback": True}, {"local_description": "current"}]
        if "remote_reoffer" in ev:
            u = ev["remote_reoffer"].get("ufrag")
            if u != self.ufrag:
                return [{"reject": {"reason": "media.unsupported", "detail": "ice-restart"}}]
            return [{"ui": "update_offered"}]
        if "answer_update" in ev:
            return [{"apply": "remote-offer+answer"}]
        return [{"ignore": "unknown-event"}]


def one_answer(offer: dict, answers: list[dict]) -> dict:
    """B§6.1 / Core §12.7 rule 4: exactly one answer is applied — the first valid one; earlier
    invalid ones end their leg with `bye media.failed`, later ones with `bye session.already-answered`."""
    applied = None
    legs = []
    for a in answers:
        frm = a.get("from")
        if applied is not None:
            legs.append({"from": frm, "bye": "session.already-answered"})
            continue
        v = check_answer(offer, a)
        if v.ok:
            applied = frm
            legs.append({"from": frm, "applied": True})
        else:
            legs.append({"from": frm, "bye": "media.failed", "code": v.code})
    return {"applied": applied, "legs": legs}


def run(v: dict) -> Any:
    """Harness entry: dispatch on `input.check`."""
    inp, ctx = v["input"], v.get("context", {})
    check = inp["check"]
    if check == "offer":
        return check_offer(inp["payload"]).to_expect()
    if check == "answer":
        return check_answer(inp["offer"], inp["payload"]).to_expect()
    if check == "role":
        return dtls_roles(inp["offer_setup"], inp["answer_setup"])
    if check == "one-answer":
        return one_answer(inp["offer"], inp["answers"])
    if check in ("candidates", "renegotiation"):
        comp = CandidateExchange(ctx) if check == "candidates" else Renegotiation(ctx)
        return {"steps": [{"emit": comp.step(st["event"])} for st in inp["steps"]]}
    raise ValueError(f"unknown media-binding check {check}")
