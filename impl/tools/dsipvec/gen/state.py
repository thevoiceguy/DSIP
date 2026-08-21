"""State-trace vectors (spec §12.4–§12.12, §14.4; plan §5.2 trace table).

Expectations below are authored from the spec tables, not recorded from an
engine. Emission ordering convention (vectors/README.md): timer stops →
sends → media → ui → timer starts; `end()` emits media stop before ui ended.
"""
from __future__ import annotations

from .. import fixtures as F
from .common import NOW, vector, uid

APH, ALA = F.did("alice-phone"), F.did("alice-laptop")
BPH, BLA = F.did("bob-phone"), F.did("bob-laptop")
ALICE, BOB, BOB_WEB = F.did("alice"), F.did("bob"), F.BOB_WEB

IDENTITIES = {APH: ALICE, ALA: ALICE, BPH: BOB, BLA: BOB, F.did("carol-phone"): F.did("carol")}
ALICE_SELF = {"device": APH, "identity": ALICE}
BOBPH_SELF = {"device": BPH, "identity": BOB}
BOBLA_SELF = {"device": BLA, "identity": BOB}


# ---------------------------------------------------------------- tiny DSL

def S(**f):
    return {"send": {k: v for k, v in f.items() if v is not None}}


def TS(name, secs):
    return {"timer": "start", "name": name, "seconds": secs}


def TP(name):
    return {"timer": "stop", "name": name}


def TF(name):
    return {"timer": "fire", "name": name}


def UI(kind, **f):
    return {"ui": kind, **f}


def MEDIA(x):
    return {"media": x}


def sess(role, state, outstanding=None):
    return {"role": role, "state": state,
            "renegotiating": outstanding is not None and outstanding["direction"] == "outbound",
            "outstanding_update": outstanding}


def step(event, emit, **sessions):
    return {"event": event, "expect": {"emit": emit, "sessions": sessions}}


def rstep(event, emit, **attempts):
    return {"event": event, "expect": {"emit": emit, "attempts": attempts}}


def trace(vid, desc, refs, self_, steps, timers=None, component="endpoint"):
    ctx = {"component": component, "start": NOW}
    if component == "endpoint":
        ctx["self"] = self_
        ctx["identities"] = IDENTITIES
        if timers:
            ctx["timers"] = timers
    return vector(f"state/{vid}", "state", desc, refs, ctx, {"steps": steps}, {})


def msg(t, label, frm, session=None, at=NOW, **f):
    m = {"type": t, "id": uid(label, at), "from": frm}
    if session is not None:
        m["session"] = session
    m.update(f)
    return m


# ---------------------------------------------------------------- shared prefixes

def initiator_to_active(sid, to=BOB_WEB, answerer=BPH):
    """place_call → ringing → answer; returns steps ending ACTIVE (with the answered-elsewhere cancel when forked)."""
    steps = [
        step({"local": "place_call", "session": sid, "to": to},
             [S(type="invite", to=to, session=sid), TS("T-Establish", 15)], **{sid: sess("initiator", "INVITING")}),
        step({"advance": 2}, [], **{sid: sess("initiator", "INVITING")}),
        step({"recv": msg("progress", "p1", answerer, sid, NOW + 2, status="ringing", ring_timeout=120)},
             [TP("T-Establish"), UI("progress", status="ringing"), TS("T-Ring", 120)], **{sid: sess("initiator", "PROCEEDING")}),
        step({"advance": 5}, [], **{sid: sess("initiator", "PROCEEDING")}),
    ]
    emit = [TP("T-Ring"), MEDIA("start"), UI("answered", answered_by="user")]
    if answerer != to:
        emit.append(S(type="cancel", to=to, session=sid, reason="session.answered-elsewhere"))
    steps.append(step({"recv": msg("answer", "a1", answerer, sid, NOW + 7, answered_by="user")}, emit,
                      **{sid: sess("initiator", "ACTIVE")}))
    return steps


def responder_to_active(sid, caller=APH, answered_by="user"):
    steps = [
        step({"recv": msg("invite", "inv", caller, None, NOW, to=BOB_WEB, expires_at=NOW + 30) | {"id": sid}},
             [UI("offered")], **{sid: sess("responder", "OFFERED")}),
        step({"local": "alert", "session": sid, "ring_timeout": 120},
             [S(type="progress", to=caller, session=sid, status="ringing", ring_timeout=120), TS("T-Ring-Local", 120)],
             **{sid: sess("responder", "ALERTING")}),
        step({"advance": 3}, [], **{sid: sess("responder", "ALERTING")}),
        step({"local": "accept", "session": sid, "answered_by": answered_by},
             [TP("T-Ring-Local"), S(type="answer", to=caller, session=sid, answered_by=answered_by), MEDIA("start")],
             **{sid: sess("responder", "ACTIVE")}),
    ]
    return steps


# ---------------------------------------------------------------- traces

def vectors() -> list[dict]:
    out = []
    sid = uid("sess")

    # §12.4 happy paths
    out.append(trace("initiator-happy-path", "invite → ringing → answer → ACTIVE → local hangup, initiator role.", ["§12.4"], ALICE_SELF,
                     initiator_to_active(sid) + [
                         step({"advance": 60}, [], **{sid: sess("initiator", "ACTIVE")}),
                         step({"local": "hangup", "session": sid},
                              [S(type="bye", to=BPH, session=sid, reason="user.hangup"), MEDIA("stop")], **{sid: sess("initiator", "ENDED")}),
                     ]))
    out.append(trace("responder-happy-path", "invite → OFFERED → alert → accept → ACTIVE → remote bye, responder role.", ["§12.4"], BOBPH_SELF,
                     responder_to_active(sid) + [
                         step({"recv": msg("bye", "bye", APH, sid, NOW + 300, reason="user.hangup")},
                              [MEDIA("stop"), UI("ended", reason="user.hangup")], **{sid: sess("responder", "ENDED")}),
                     ]))
    out.append(trace("initiator-remote-bye", "Responder hangs up first.", ["§12.4"], ALICE_SELF,
                     initiator_to_active(sid) + [
                         step({"recv": msg("bye", "bye", BPH, sid, NOW + 60, reason="user.hangup")},
                              [MEDIA("stop"), UI("ended", reason="user.hangup")], **{sid: sess("initiator", "ENDED")}),
                         step({"recv": msg("bye", "bye2", BPH, sid, NOW + 61, reason="user.hangup")},
                              [{"drop": "ended-session"}], **{sid: sess("initiator", "ENDED")}),
                     ]))
    out.append(trace("responder-declines", "User declines while alerting → reject user.declined.", ["§12.4"], BOBPH_SELF,
                     responder_to_active(sid)[:3] + [
                         step({"local": "decline", "session": sid},
                              [TP("T-Ring-Local"), S(type="reject", to=APH, session=sid, reason="user.declined")],
                              **{sid: sess("responder", "ENDED")}),
                     ]))
    out.append(trace("responder-auto-reject-policy", "Policy rejects at OFFERED without alerting.", ["§12.4", "§19"], BOBPH_SELF, [
        responder_to_active(sid)[0],
        step({"local": "auto_reject", "session": sid, "reason": "policy.first-contact-required"},
             [S(type="reject", to=APH, session=sid, reason="policy.first-contact-required")], **{sid: sess("responder", "ENDED")}),
    ]))
    out.append(trace("responder-cancel-at-offered", "Cancel arrives before alerting: discard, no missed call surfaced.", ["§12.4"], BOBPH_SELF, [
        responder_to_active(sid)[0],
        step({"recv": msg("cancel", "c", APH, sid, NOW + 1, reason="user.cancelled")},
             [UI("ended", reason="user.cancelled")], **{sid: sess("responder", "ENDED")}),
    ]))
    out.append(trace("initiator-rejected-while-proceeding", "Attempt outcome reject ends the session; a late answer gets bye (Impl: session.failed).",
                     ["§12.4", "§12.7"], ALICE_SELF, initiator_to_active(sid)[:4] + [
                         step({"recv": msg("reject", "r", BPH, sid, NOW + 7, reason="user.declined")},
                              [TP("T-Ring"), UI("ended", reason="user.declined")], **{sid: sess("initiator", "ENDED")}),
                         step({"recv": msg("answer", "late", BLA, sid, NOW + 8, answered_by="user")},
                              [S(type="bye", to=BLA, session=sid, reason="session.failed")], **{sid: sess("initiator", "ENDED")}),
                     ]))
    out.append(trace("initiator-rejected-while-inviting", "Reject before any progress.", ["§12.4"], ALICE_SELF, [
        initiator_to_active(sid)[0],
        step({"recv": msg("reject", "r", BPH, sid, NOW + 1, reason="endpoint.busy")},
             [TP("T-Establish"), UI("ended", reason="endpoint.busy")], **{sid: sess("initiator", "ENDED")}),
    ]))
    out.append(trace("unknown-session-rejected", "Message for a session this endpoint does not know → error session.unknown-session.",
                     ["§12.2"], ALICE_SELF, [
                         step({"recv": msg("bye", "b", BPH, uid("nope"), NOW, reason="user.hangup")},
                              [S(type="error", to=BPH, session=uid("nope"), reason="session.unknown-session", in_reply_to=uid("b"))]),
                     ]))
    out.append(trace("invalid-state-messages", "bye/update/info before ACTIVE and answer at a responder → error session.invalid-state.",
                     ["§12.4", "§12.8", "§12.12"], ALICE_SELF, initiator_to_active(sid)[:3] + [
                         step({"recv": msg("bye", "b", BPH, sid, NOW + 3, reason="user.hangup")},
                              [S(type="error", to=BPH, session=sid, reason="session.invalid-state", in_reply_to=uid("b", NOW + 3))],
                              **{sid: sess("initiator", "PROCEEDING")}),
                         step({"recv": msg("update", "u", BPH, sid, NOW + 3)},
                              [S(type="error", to=BPH, session=sid, reason="session.invalid-state", in_reply_to=uid("u", NOW + 3))],
                              **{sid: sess("initiator", "PROCEEDING")}),
                         step({"recv": msg("info", "i", BPH, sid, NOW + 3, about="transport:webrtc")},
                              [S(type="error", to=BPH, session=sid, reason="session.invalid-state", in_reply_to=uid("i", NOW + 3))],
                              **{sid: sess("initiator", "PROCEEDING")}),
                         step({"recv": msg("cancel", "c", BPH, sid, NOW + 3, reason="user.cancelled")},
                              [S(type="error", to=BPH, session=sid, reason="session.invalid-state", in_reply_to=uid("c", NOW + 3))],
                              **{sid: sess("initiator", "PROCEEDING")}),
                     ]))

    # §12.9 timers
    out.append(trace("timer-t-establish", "No progress or answer within T-Establish → cancel session.timeout.", ["§12.9"], ALICE_SELF, [
        initiator_to_active(sid)[0],
        step({"advance": 14}, [], **{sid: sess("initiator", "INVITING")}),
        step({"advance": 1}, [TF("T-Establish"), S(type="cancel", to=BOB_WEB, session=sid, reason="session.timeout"),
                              UI("ended", reason="session.timeout")], **{sid: sess("initiator", "ENDED")}),
    ]))
    out.append(trace("timer-t-establish-configured", "T-Establish configured to 40 s (within 5–60 bounds).", ["§12.9"], ALICE_SELF, [
        step({"local": "place_call", "session": sid, "to": BOB_WEB},
             [S(type="invite", to=BOB_WEB, session=sid), TS("T-Establish", 40)], **{sid: sess("initiator", "INVITING")}),
        step({"advance": 40}, [TF("T-Establish"), S(type="cancel", to=BOB_WEB, session=sid, reason="session.timeout"),
                              UI("ended", reason="session.timeout")], **{sid: sess("initiator", "ENDED")}),
    ], timers={"t_establish": 40}))
    out.append(trace("timer-t-ring-default", "Ringing without ring_timeout: T-Ring 120 s then cancel session.timeout.", ["§12.9"], ALICE_SELF, [
        initiator_to_active(sid)[0],
        step({"recv": msg("progress", "p", BPH, sid, NOW, status="ringing")},
             [TP("T-Establish"), UI("progress", status="ringing"), TS("T-Ring", 120)], **{sid: sess("initiator", "PROCEEDING")}),
        step({"advance": 119}, [], **{sid: sess("initiator", "PROCEEDING")}),
        step({"advance": 1}, [TF("T-Ring"), S(type="cancel", to=BOB_WEB, session=sid, reason="session.timeout"),
                              UI("ended", reason="session.timeout")], **{sid: sess("initiator", "ENDED")}),
    ]))
    out.append(trace("timer-t-ring-extension-honored", "ring_timeout 240 extends T-Ring; a later ringing with 300 restarts at the upper bound.",
                     ["§12.9", "§12.10"], ALICE_SELF, [
                         initiator_to_active(sid)[0],
                         step({"recv": msg("progress", "p", BPH, sid, NOW, status="ringing", ring_timeout=240)},
                              [TP("T-Establish"), UI("progress", status="ringing"), TS("T-Ring", 240)], **{sid: sess("initiator", "PROCEEDING")}),
                         step({"advance": 200}, [], **{sid: sess("initiator", "PROCEEDING")}),
                         step({"recv": msg("progress", "p2", BPH, sid, NOW + 200, status="ringing", ring_timeout=300)},
                              [UI("progress", status="ringing"), TS("T-Ring", 300)], **{sid: sess("initiator", "PROCEEDING")}),
                         step({"advance": 299}, [], **{sid: sess("initiator", "PROCEEDING")}),
                         step({"advance": 1}, [TF("T-Ring"), S(type="cancel", to=BOB_WEB, session=sid, reason="session.timeout"),
                                               UI("ended", reason="session.timeout")], **{sid: sess("initiator", "ENDED")}),
                     ]))
    out.append(trace("timer-repeat-ringing-no-restart", "A second ringing progress without ring_timeout does not restart T-Ring (Impl, spec-gap 4).",
                     ["§12.9"], ALICE_SELF, [
                         initiator_to_active(sid)[0],
                         step({"recv": msg("progress", "p", BPH, sid, NOW, status="ringing")},
                              [TP("T-Establish"), UI("progress", status="ringing"), TS("T-Ring", 120)], **{sid: sess("initiator", "PROCEEDING")}),
                         step({"advance": 100}, [], **{sid: sess("initiator", "PROCEEDING")}),
                         step({"recv": msg("progress", "p2", BLA, sid, NOW + 100, status="ringing")},
                              [UI("progress", status="ringing")], **{sid: sess("initiator", "PROCEEDING")}),
                         step({"advance": 20}, [TF("T-Ring"), S(type="cancel", to=BOB_WEB, session=sid, reason="session.timeout"),
                                                UI("ended", reason="session.timeout")], **{sid: sess("initiator", "ENDED")}),
                     ]))
    out.append(trace("timer-t-queue", "queued replaces T-Ring with T-Queue; ringing cancels T-Queue; re-queue is capped at 1800 s.",
                     ["§12.9", "§12.10"], ALICE_SELF, [
                         initiator_to_active(sid)[0],
                         step({"recv": msg("progress", "q1", BPH, sid, NOW, status="queued", queue_timeout=600)},
                              [TP("T-Establish"), UI("progress", status="queued"), TS("T-Queue", 600)], **{sid: sess("initiator", "PROCEEDING")}),
                         step({"advance": 300}, [], **{sid: sess("initiator", "PROCEEDING")}),
                         step({"recv": msg("progress", "r1", BPH, sid, NOW + 300, status="ringing")},
                              [UI("progress", status="ringing"), TP("T-Queue"), TS("T-Ring", 120)], **{sid: sess("initiator", "PROCEEDING")}),
                         step({"recv": msg("progress", "q2", BPH, sid, NOW + 300, status="queued", queue_timeout=2400)},
                              [UI("progress", status="queued"), TP("T-Ring"), TS("T-Queue", 1800)], **{sid: sess("initiator", "PROCEEDING")}),
                         step({"advance": 1799}, [], **{sid: sess("initiator", "PROCEEDING")}),
                         step({"advance": 1}, [TF("T-Queue"), S(type="cancel", to=BOB_WEB, session=sid, reason="session.timeout"),
                                               UI("ended", reason="session.timeout")], **{sid: sess("initiator", "ENDED")}),
                     ]))
    out.append(trace("timer-t-queue-requeue-limit", "Three consecutive re-queues are honored; the fourth is treated as T-Queue expiry (Impl, spec-gap 11).",
                     ["§12.10"], ALICE_SELF, [
                         initiator_to_active(sid)[0],
                         step({"recv": msg("progress", "q1", BPH, sid, NOW, status="queued", queue_timeout=60)},
                              [TP("T-Establish"), UI("progress", status="queued"), TS("T-Queue", 60)], **{sid: sess("initiator", "PROCEEDING")}),
                         step({"recv": msg("progress", "q2", BPH, sid, NOW, status="queued", queue_timeout=60)},
                              [UI("progress", status="queued"), TS("T-Queue", 60)], **{sid: sess("initiator", "PROCEEDING")}),
                         step({"recv": msg("progress", "q3", BPH, sid, NOW, status="queued", queue_timeout=60)},
                              [UI("progress", status="queued"), TS("T-Queue", 60)], **{sid: sess("initiator", "PROCEEDING")}),
                         step({"recv": msg("progress", "q4", BPH, sid, NOW, status="queued", queue_timeout=60)},
                              [UI("progress", status="queued"), TP("T-Queue"), S(type="cancel", to=BOB_WEB, session=sid, reason="session.timeout"),
                               UI("ended", reason="session.timeout")], **{sid: sess("initiator", "ENDED")}),
                     ]))
    out.append(trace("timer-queued-user-abandons", "The initiating user can abandon a queued session via cancel user.cancelled.", ["§12.10"], ALICE_SELF, [
        initiator_to_active(sid)[0],
        step({"recv": msg("progress", "q1", BPH, sid, NOW, status="queued", queue_timeout=900)},
             [TP("T-Establish"), UI("progress", status="queued"), TS("T-Queue", 900)], **{sid: sess("initiator", "PROCEEDING")}),
        step({"local": "cancel", "session": sid}, [TP("T-Queue"), S(type="cancel", to=BOB_WEB, session=sid, reason="user.cancelled")],
             **{sid: sess("initiator", "ENDED")}),
    ]))
    out.append(trace("timer-trying-backstop", "A trying progress stops T-Establish; T-Ring is started as the backstop (Impl, spec-gap 4); unknown status = trying.",
                     ["§12.9", "§12.10"], ALICE_SELF, [
                         initiator_to_active(sid)[0],
                         step({"recv": msg("progress", "t", BPH, sid, NOW, status="trying")},
                              [TP("T-Establish"), UI("progress", status="trying"), TS("T-Ring", 120)], **{sid: sess("initiator", "PROCEEDING")}),
                         step({"recv": msg("progress", "x", BPH, sid, NOW, status="pondering")},
                              [UI("progress", status="trying")], **{sid: sess("initiator", "PROCEEDING")}),
                     ]))
    out.append(trace("timer-t-ring-local", "Responder's local ring timer expires → reject user.no-answer.", ["§12.9"], BOBPH_SELF,
                     responder_to_active(sid)[:2] + [
                         step({"advance": 119}, [], **{sid: sess("responder", "ALERTING")}),
                         step({"advance": 1}, [TF("T-Ring-Local"), S(type="reject", to=APH, session=sid, reason="user.no-answer"),
                                               UI("ended", reason="user.no-answer")], **{sid: sess("responder", "ENDED")}),
                     ]))
    out.append(trace("timer-t-ring-local-follows-advertised", "T-Ring-Local follows the advertised ring_timeout (45 s).", ["§12.9"], BOBPH_SELF, [
        responder_to_active(sid)[0],
        step({"local": "alert", "session": sid, "ring_timeout": 45},
             [S(type="progress", to=APH, session=sid, status="ringing", ring_timeout=45), TS("T-Ring-Local", 45)],
             **{sid: sess("responder", "ALERTING")}),
        step({"advance": 45}, [TF("T-Ring-Local"), S(type="reject", to=APH, session=sid, reason="user.no-answer"),
                               UI("ended", reason="user.no-answer")], **{sid: sess("responder", "ENDED")}),
    ]))
    out.append(trace("invite-expires-before-alerting", "Invite validity lapses before alerting begins → reject session.expired.", ["§12.9"], BOBPH_SELF, [
        responder_to_active(sid)[0],
        step({"advance": 31}, [], **{sid: sess("responder", "OFFERED")}),
        step({"local": "alert", "session": sid}, [S(type="reject", to=APH, session=sid, reason="session.expired")],
             **{sid: sess("responder", "ENDED")}),
    ]))
    out.append(trace("invite-expiry-irrelevant-once-alerting", "Once ALERTING, T-Ring-Local governs, not expires_at.", ["§12.9"], BOBPH_SELF, [
        responder_to_active(sid)[0],
        step({"local": "alert", "session": sid}, [S(type="progress", to=APH, session=sid, status="ringing"), TS("T-Ring-Local", 120)],
             **{sid: sess("responder", "ALERTING")}),
        step({"advance": 60}, [], **{sid: sess("responder", "ALERTING")}),
        step({"local": "accept", "session": sid, "answered_by": "user"},
             [TP("T-Ring-Local"), S(type="answer", to=APH, session=sid, answered_by="user"), MEDIA("start")], **{sid: sess("responder", "ACTIVE")}),
    ]))

    # §12.5 cancel/answer race
    out.append(trace("race-initiator-cancel-then-answer", "Initiator cancels; a crossing answer arrives → bye session.cancelled; session not resurrected.",
                     ["§12.5"], ALICE_SELF, initiator_to_active(sid)[:3] + [
                         step({"local": "cancel", "session": sid}, [TP("T-Ring"), S(type="cancel", to=BOB_WEB, session=sid, reason="user.cancelled")],
                              **{sid: sess("initiator", "ENDED")}),
                         step({"recv": msg("answer", "a", BPH, sid, NOW + 3, answered_by="user")},
                              [S(type="bye", to=BPH, session=sid, reason="session.cancelled")], **{sid: sess("initiator", "ENDED")}),
                         step({"recv": msg("progress", "p9", BLA, sid, NOW + 3, status="ringing")},
                              [{"drop": "ended-session"}], **{sid: sess("initiator", "ENDED")}),
                     ]))
    out.append(trace("race-responder-crossed-cancel", "Responder answered; a crossing cancel arrives before any post-answer message → teardown, no error.",
                     ["§12.5"], BOBPH_SELF, responder_to_active(sid) + [
                         step({"recv": msg("cancel", "c", APH, sid, NOW + 3, reason="user.cancelled")},
                              [MEDIA("stop"), UI("ended", reason="user.cancelled")], **{sid: sess("responder", "ENDED")}),
                     ]))
    out.append(trace("race-responder-cancel-after-post-answer-traffic", "Cancel for an ACTIVE session after the initiator has spoken post-answer → error session.invalid-state (Impl, spec-gap 1).",
                     ["§12.4", "§12.11"], BOBPH_SELF, responder_to_active(sid) + [
                         step({"recv": msg("info", "i", APH, sid, NOW + 3, about="transport:webrtc")},
                              [{"info": {"about": "transport:webrtc"}}], **{sid: sess("responder", "ACTIVE")}),
                         step({"recv": msg("cancel", "c", APH, sid, NOW + 4, reason="user.cancelled")},
                              [S(type="error", to=APH, session=sid, reason="session.invalid-state", in_reply_to=uid("c", NOW + 4))],
                              **{sid: sess("responder", "ACTIVE")}),
                     ]))
    out.append(trace("race-responder-answered-elsewhere-at-answering-leg",
                     "A per-leg cancel session.answered-elsewhere that reaches the leg which answered is misrouted, not crossed: "
                     "error session.invalid-state, session stays ACTIVE (Impl, spec-gap 1).", ["§12.5", "§12.7"], BOBPH_SELF,
                     responder_to_active(sid) + [
                         step({"recv": msg("cancel", "c", APH, sid, NOW + 3, reason="session.answered-elsewhere")},
                              [S(type="error", to=APH, session=sid, reason="session.invalid-state", in_reply_to=uid("c", NOW + 3))],
                              **{sid: sess("responder", "ACTIVE")}),
                     ]))
    out.append(trace("race-timeout-cancel-then-answer", "T-Ring expiry cancels; a late answer still gets bye session.cancelled.", ["§12.5", "§12.9"], ALICE_SELF, [
        initiator_to_active(sid)[0],
        step({"recv": msg("progress", "p", BPH, sid, NOW, status="ringing")},
             [TP("T-Establish"), UI("progress", status="ringing"), TS("T-Ring", 120)], **{sid: sess("initiator", "PROCEEDING")}),
        step({"advance": 120}, [TF("T-Ring"), S(type="cancel", to=BOB_WEB, session=sid, reason="session.timeout"),
                                UI("ended", reason="session.timeout")], **{sid: sess("initiator", "ENDED")}),
        step({"recv": msg("answer", "a", BPH, sid, NOW + 120, answered_by="user")},
             [S(type="bye", to=BPH, session=sid, reason="session.cancelled")], **{sid: sess("initiator", "ENDED")}),
    ]))

    # §12.6 glare
    ours, theirs_later, theirs_earlier = uid("g-ours", NOW), uid("g-theirs", NOW + 1), uid("g-theirs", NOW - 1)
    out.append(trace("glare-we-win", "Our invite has the smaller ULID: reject the inbound with session.glare and continue as initiator.", ["§12.6"], ALICE_SELF, [
        step({"local": "place_call", "session": ours, "to": BOB}, [S(type="invite", to=BOB, session=ours), TS("T-Establish", 15)],
             **{ours: sess("initiator", "INVITING")}),
        step({"recv": msg("invite", "g-theirs", BPH, None, NOW + 1, to=ALICE, expires_at=NOW + 31)},
             [S(type="reject", to=BPH, session=theirs_later, reason="session.glare")],
             **{ours: sess("initiator", "INVITING"), theirs_later: sess("responder", "ENDED")}),
        step({"recv": msg("progress", "p", BPH, ours, NOW + 2, status="ringing")},
             [TP("T-Establish"), UI("progress", status="ringing"), TS("T-Ring", 120)], **{ours: sess("initiator", "PROCEEDING")}),
    ]))
    out.append(trace("glare-we-lose", "Inbound invite has the smaller ULID: withdraw ours with session.glare (Impl, spec-gap 2) and proceed as responder.", ["§12.6"], ALICE_SELF, [
        step({"local": "place_call", "session": ours, "to": BOB}, [S(type="invite", to=BOB, session=ours), TS("T-Establish", 15)],
             **{ours: sess("initiator", "INVITING")}),
        step({"recv": msg("invite", "g-theirs", BPH, None, NOW - 1, to=ALICE, expires_at=NOW + 29)},
             [TP("T-Establish"), S(type="cancel", to=BOB, session=ours, reason="session.glare"), UI("ended", reason="session.glare"), UI("offered")],
             **{ours: sess("initiator", "ENDED"), theirs_earlier: sess("responder", "OFFERED")}),
        step({"local": "alert", "session": theirs_earlier},
             [S(type="progress", to=BPH, session=theirs_earlier, status="ringing"), TS("T-Ring-Local", 120)],
             **{theirs_earlier: sess("responder", "ALERTING")}),
        step({"recv": msg("reject", "r", BPH, ours, NOW, reason="session.glare")}, [{"drop": "ended-session"}],
             **{ours: sess("initiator", "ENDED")}),
    ]))
    out.append(trace("glare-equal-ids", "Pathological equal ids: both invites rejected with session.glare; retry hint surfaced.", ["§12.6"], ALICE_SELF, [
        step({"local": "place_call", "session": ours, "to": BOB}, [S(type="invite", to=BOB, session=ours), TS("T-Establish", 15)],
             **{ours: sess("initiator", "INVITING")}),
        step({"recv": msg("invite", "g-ours", BPH, None, NOW, to=ALICE, expires_at=NOW + 30)},
             [TP("T-Establish"), S(type="cancel", to=BOB, session=ours, reason="session.glare"), UI("ended", reason="session.glare"),
              S(type="reject", to=BPH, session=ours, reason="session.glare"), UI("glare_retry")],
             **{ours: sess("initiator", "ENDED")}),
    ]))
    out.append(trace("glare-not-triggered-different-identity", "An inbound invite from an unrelated identity while we are inviting bob is not glare.", ["§12.6"], ALICE_SELF, [
        step({"local": "place_call", "session": ours, "to": BOB}, [S(type="invite", to=BOB, session=ours), TS("T-Establish", 15)],
             **{ours: sess("initiator", "INVITING")}),
        step({"recv": msg("invite", "carol", F.did("carol-phone"), None, NOW, to=ALICE, expires_at=NOW + 30)}, [UI("offered")],
             **{ours: sess("initiator", "INVITING"), uid("carol"): sess("responder", "OFFERED")}),
    ]))

    # §12.7 forking (initiator side)
    out.append(trace("fork-first-answer-wins", "Two legs ring; phone answers → cancel answered-elsewhere; laptop's late answer → bye already-answered; late progress → invalid-state.",
                     ["§12.7", "§12.4"], ALICE_SELF, [
                         initiator_to_active(sid)[0],
                         step({"recv": msg("progress", "p1", BPH, sid, NOW, status="ringing")},
                              [TP("T-Establish"), UI("progress", status="ringing"), TS("T-Ring", 120)], **{sid: sess("initiator", "PROCEEDING")}),
                         step({"recv": msg("progress", "p2", BLA, sid, NOW, status="ringing")},
                              [UI("progress", status="ringing")], **{sid: sess("initiator", "PROCEEDING")}),
                         step({"recv": msg("answer", "a1", BPH, sid, NOW + 5, answered_by="user")},
                              [TP("T-Ring"), MEDIA("start"), UI("answered", answered_by="user"),
                               S(type="cancel", to=BOB_WEB, session=sid, reason="session.answered-elsewhere")], **{sid: sess("initiator", "ACTIVE")}),
                         step({"recv": msg("answer", "a2", BLA, sid, NOW + 6, answered_by="user")},
                              [S(type="bye", to=BLA, session=sid, reason="session.already-answered")], **{sid: sess("initiator", "ACTIVE")}),
                         step({"recv": msg("progress", "p3", BLA, sid, NOW + 6, status="ringing")},
                              [S(type="error", to=BLA, session=sid, reason="session.invalid-state", in_reply_to=uid("p3", NOW + 6))],
                              **{sid: sess("initiator", "ACTIVE")}),
                         step({"recv": msg("answer", "a3", BPH, sid, NOW + 7, answered_by="user")},
                              [S(type="error", to=BPH, session=sid, reason="session.invalid-state", in_reply_to=uid("a3", NOW + 7))],
                              **{sid: sess("initiator", "ACTIVE")}),
                     ]))
    out.append(trace("direct-device-call-no-fork-cancel", "Invite addressed to a device DID: its answer produces no answered-elsewhere cancel (Impl, spec-gap 5).",
                     ["§12.7"], ALICE_SELF, initiator_to_active(sid, to=BPH, answerer=BPH)))
    out.append(trace("fork-answer-before-progress", "Answer straight from INVITING (no progress) is valid.", ["§12.4"], ALICE_SELF, [
        initiator_to_active(sid)[0],
        step({"recv": msg("answer", "a", BPH, sid, NOW + 1, answered_by="service")},
             [TP("T-Establish"), MEDIA("start"), UI("answered", answered_by="service"),
              S(type="cancel", to=BOB_WEB, session=sid, reason="session.answered-elsewhere")], **{sid: sess("initiator", "ACTIVE")}),
    ]))
    out.append(trace("fork-responder-answered-elsewhere", "Laptop leg receives cancel session.answered-elsewhere: stops alerting, no missed call.", ["§12.7", "§12.11"], BOBLA_SELF,
                     responder_to_active(sid)[:2] + [
                         step({"recv": msg("cancel", "c", APH, sid, NOW + 5, reason="session.answered-elsewhere")},
                              [TP("T-Ring-Local"), UI("ended", reason="session.answered-elsewhere")], **{sid: sess("responder", "ENDED")}),
                     ]))
    out.append(trace("responder-missed-call-on-user-cancel", "Alerting leg receives cancel user.cancelled: missed call surfaced.", ["§12.4", "§12.11"], BOBPH_SELF,
                     responder_to_active(sid)[:2] + [
                         step({"recv": msg("cancel", "c", APH, sid, NOW + 5, reason="user.cancelled")},
                              [TP("T-Ring-Local"), UI("missed_call"), UI("ended", reason="user.cancelled")], **{sid: sess("responder", "ENDED")}),
                     ]))
    out.append(trace("responder-missed-call-on-timeout-cancel", "Alerting leg receives cancel session.timeout: missed call surfaced.", ["§12.4"], BOBPH_SELF,
                     responder_to_active(sid)[:2] + [
                         step({"recv": msg("cancel", "c", APH, sid, NOW + 5, reason="session.timeout")},
                              [TP("T-Ring-Local"), UI("missed_call"), UI("ended", reason="session.timeout")], **{sid: sess("responder", "ENDED")}),
                     ]))

    # §12.8 renegotiation
    u1, u2, u3, u4 = (uid(f"u{i}", NOW + 100 + i) for i in range(1, 5))
    out.append(trace("renegotiation-update-answer-reject", "update answered via in_reply_to; a second update rejected keeps prior state; third blocked while outstanding; bye wins.",
                     ["§12.8"], ALICE_SELF, initiator_to_active(sid) + [
                         step({"local": "update", "session": sid, "id": u1}, [S(type="update", to=BPH, session=sid, id=u1)],
                              **{sid: sess("initiator", "ACTIVE", {"id": u1, "direction": "outbound"})}),
                         step({"recv": msg("answer", "ua1", BPH, sid, NOW + 102, answered_by="user", in_reply_to=u1)},
                              [MEDIA("apply_update")], **{sid: sess("initiator", "ACTIVE")}),
                         step({"local": "update", "session": sid, "id": u2}, [S(type="update", to=BPH, session=sid, id=u2)],
                              **{sid: sess("initiator", "ACTIVE", {"id": u2, "direction": "outbound"})}),
                         step({"recv": msg("reject", "ur2", BPH, sid, NOW + 103, reason="media.unsupported", in_reply_to=u2)},
                              [UI("update_rejected", reason="media.unsupported")], **{sid: sess("initiator", "ACTIVE")}),
                         step({"recv": msg("reject", "ur2b", BPH, sid, NOW + 103, reason="media.unsupported", in_reply_to=u2)},
                              [{"drop": "stale-update-reply"}], **{sid: sess("initiator", "ACTIVE")}),
                         step({"local": "update", "session": sid, "id": u3}, [S(type="update", to=BPH, session=sid, id=u3)],
                              **{sid: sess("initiator", "ACTIVE", {"id": u3, "direction": "outbound"})}),
                         step({"local": "update", "session": sid, "id": u4}, [{"refused": "update-pending"}],
                              **{sid: sess("initiator", "ACTIVE", {"id": u3, "direction": "outbound"})}),
                         step({"recv": msg("bye", "bye", BPH, sid, NOW + 110, reason="user.hangup")},
                              [MEDIA("stop"), UI("ended", reason="user.hangup")], **{sid: sess("initiator", "ENDED")}),
                     ]))
    out.append(trace("renegotiation-inbound-update-answered", "Receiver of an update answers it; a local update is refused while the inbound one is pending.",
                     ["§12.8"], BOBPH_SELF, responder_to_active(sid) + [
                         step({"recv": msg("update", "u1", APH, sid, NOW + 101)}, [UI("update_offered")],
                              **{sid: sess("responder", "ACTIVE", {"id": u1, "direction": "inbound"})}),
                         step({"local": "update", "session": sid, "id": u2}, [{"refused": "update-pending"}],
                              **{sid: sess("responder", "ACTIVE", {"id": u1, "direction": "inbound"})}),
                         step({"local": "answer_update", "session": sid, "in_reply_to": u1},
                              [S(type="answer", to=APH, session=sid, answered_by="user", in_reply_to=u1), MEDIA("apply_update")],
                              **{sid: sess("responder", "ACTIVE")}),
                         step({"recv": msg("update", "u2", APH, sid, NOW + 102)}, [UI("update_offered")],
                              **{sid: sess("responder", "ACTIVE", {"id": u2, "direction": "inbound"})}),
                         step({"local": "reject_update", "session": sid, "in_reply_to": u2, "reason": "media.unsupported"},
                              [S(type="reject", to=APH, session=sid, reason="media.unsupported", in_reply_to=u2)],
                              **{sid: sess("responder", "ACTIVE")}),
                     ]))
    out.append(trace("renegotiation-second-update-same-direction", "Second update from the same sender while its first is pending → error session.update-pending; neither processed (Impl, spec-gap 3).",
                     ["§12.8"], BOBPH_SELF, responder_to_active(sid) + [
                         step({"recv": msg("update", "u1", APH, sid, NOW + 101)}, [UI("update_offered")],
                              **{sid: sess("responder", "ACTIVE", {"id": u1, "direction": "inbound"})}),
                         step({"recv": msg("update", "u2", APH, sid, NOW + 102)},
                              [S(type="error", to=APH, session=sid, reason="session.update-pending", in_reply_to=u2)],
                              **{sid: sess("responder", "ACTIVE")}),
                         step({"local": "answer_update", "session": sid, "in_reply_to": u1}, [{"refused": "no-pending-update"}],
                              **{sid: sess("responder", "ACTIVE")}),
                     ]))
    uo, ui_earlier, ui_later = uid("uo", NOW + 100), uid("ui", NOW + 99), uid("ui", NOW + 101)
    out.append(trace("renegotiation-update-glare-inbound-wins", "Both sides sent updates; the inbound has the smaller id → ours is dropped, theirs is offered.",
                     ["§12.8"], ALICE_SELF, initiator_to_active(sid) + [
                         step({"local": "update", "session": sid, "id": uo}, [S(type="update", to=BPH, session=sid, id=uo)],
                              **{sid: sess("initiator", "ACTIVE", {"id": uo, "direction": "outbound"})}),
                         step({"recv": msg("update", "ui", BPH, sid, NOW + 99)},
                              [UI("update_rejected", reason="session.glare"), UI("update_offered")],
                              **{sid: sess("initiator", "ACTIVE", {"id": ui_earlier, "direction": "inbound"})}),
                         step({"recv": msg("reject", "r", BPH, sid, NOW + 100, reason="session.glare", in_reply_to=uo)},
                              [{"drop": "stale-update-reply"}], **{sid: sess("initiator", "ACTIVE", {"id": ui_earlier, "direction": "inbound"})}),
                         step({"local": "answer_update", "session": sid, "in_reply_to": ui_earlier},
                              [S(type="answer", to=BPH, session=sid, answered_by="user", in_reply_to=ui_earlier), MEDIA("apply_update")],
                              **{sid: sess("initiator", "ACTIVE")}),
                     ]))
    out.append(trace("renegotiation-update-glare-ours-wins", "Both sides sent updates; ours has the smaller id → reject theirs with session.glare, keep ours.",
                     ["§12.8"], ALICE_SELF, initiator_to_active(sid) + [
                         step({"local": "update", "session": sid, "id": uo}, [S(type="update", to=BPH, session=sid, id=uo)],
                              **{sid: sess("initiator", "ACTIVE", {"id": uo, "direction": "outbound"})}),
                         step({"recv": msg("update", "ui", BPH, sid, NOW + 101)},
                              [S(type="reject", to=BPH, session=sid, reason="session.glare", in_reply_to=ui_later)],
                              **{sid: sess("initiator", "ACTIVE", {"id": uo, "direction": "outbound"})}),
                         step({"recv": msg("answer", "ua", BPH, sid, NOW + 102, answered_by="user", in_reply_to=uo)},
                              [MEDIA("apply_update")], **{sid: sess("initiator", "ACTIVE")}),
                     ]))
    out.append(trace("renegotiation-bye-discards-pending-update", "bye while our update is outstanding: bye wins, update discarded.", ["§12.8"], ALICE_SELF,
                     initiator_to_active(sid) + [
                         step({"local": "update", "session": sid, "id": u1}, [S(type="update", to=BPH, session=sid, id=u1)],
                              **{sid: sess("initiator", "ACTIVE", {"id": u1, "direction": "outbound"})}),
                         step({"local": "hangup", "session": sid}, [S(type="bye", to=BPH, session=sid, reason="user.hangup"), MEDIA("stop")],
                              **{sid: sess("initiator", "ENDED")}),
                     ]))

    # §12.12 info
    out.append(trace("info-active-only", "info in ACTIVE is delivered; unknown about is ignored; info after ENDED is dropped.", ["§12.12"], ALICE_SELF,
                     initiator_to_active(sid) + [
                         step({"recv": msg("info", "i1", BPH, sid, NOW + 8, about="transport:webrtc")}, [{"info": {"about": "transport:webrtc"}}],
                              **{sid: sess("initiator", "ACTIVE")}),
                         step({"recv": msg("info", "i2", BPH, sid, NOW + 8, about="x-future:thing")}, [{"drop": "unknown-about"}],
                              **{sid: sess("initiator", "ACTIVE")}),
                         step({"local": "info", "session": sid}, [S(type="info", to=BPH, session=sid)], **{sid: sess("initiator", "ACTIVE")}),
                         step({"local": "hangup", "session": sid}, [S(type="bye", to=BPH, session=sid, reason="user.hangup"), MEDIA("stop")],
                              **{sid: sess("initiator", "ENDED")}),
                         step({"recv": msg("info", "i3", BPH, sid, NOW + 9, about="transport:webrtc")}, [{"drop": "ended-session"}],
                              **{sid: sess("initiator", "ENDED")}),
                     ]))

    # §14.3–14.4 screening
    su = uid("screen-up", NOW + 20)
    out.append(trace("screening-responder", "Callee answers in screening mode, then escalates with update answered_by user.", ["§14.4"], BOBPH_SELF,
                     responder_to_active(sid, answered_by="screening") + [
                         step({"local": "update", "session": sid, "id": su, "answered_by": "user"},
                              [S(type="update", to=APH, session=sid, id=su, answered_by="user")],
                              **{sid: sess("responder", "ACTIVE", {"id": su, "direction": "outbound"})}),
                         step({"recv": msg("answer", "sa", APH, sid, NOW + 21, answered_by="user", in_reply_to=su)},
                              [MEDIA("apply_update")], **{sid: sess("responder", "ACTIVE")}),
                     ]))
    out.append(trace("screening-initiator", "Caller sees screening mode, then the escalation update carrying answered_by user.", ["§14.3", "§14.4"], ALICE_SELF,
                     initiator_to_active(sid)[:4] + [
                         step({"recv": msg("answer", "a1", BPH, sid, NOW + 7, answered_by="screening")},
                              [TP("T-Ring"), MEDIA("start"), UI("answered", answered_by="screening"),
                               S(type="cancel", to=BOB_WEB, session=sid, reason="session.answered-elsewhere")], **{sid: sess("initiator", "ACTIVE")}),
                         step({"recv": msg("update", "screen-up", BPH, sid, NOW + 20, answered_by="user")},
                              [UI("update_offered"), UI("answered", answered_by="user")],
                              **{sid: sess("initiator", "ACTIVE", {"id": su, "direction": "inbound"})}),
                         step({"local": "answer_update", "session": sid, "in_reply_to": su},
                              [S(type="answer", to=BPH, session=sid, answered_by="user", in_reply_to=su), MEDIA("apply_update")],
                              **{sid: sess("initiator", "ACTIVE")}),
                     ]))
    out.append(trace("screening-declined-with-bye", "Screening ends with bye user.declined.", ["§14.4"], ALICE_SELF,
                     initiator_to_active(sid)[:4] + [
                         step({"recv": msg("answer", "a1", BPH, sid, NOW + 7, answered_by="screening")},
                              [TP("T-Ring"), MEDIA("start"), UI("answered", answered_by="screening"),
                               S(type="cancel", to=BOB_WEB, session=sid, reason="session.answered-elsewhere")], **{sid: sess("initiator", "ACTIVE")}),
                         step({"recv": msg("bye", "b", BPH, sid, NOW + 15, reason="user.declined")},
                              [MEDIA("stop"), UI("ended", reason="user.declined")], **{sid: sess("initiator", "ENDED")}),
                     ]))
    out.append(trace("unknown-answered-by-renders-service", "Unknown answered_by value surfaces as service at the caller.", ["§14.3"], ALICE_SELF, [
        initiator_to_active(sid)[0],
        step({"recv": msg("answer", "a", BPH, sid, NOW + 1, answered_by="butler")},
             [TP("T-Establish"), MEDIA("start"), UI("answered", answered_by="service"),
              S(type="cancel", to=BOB_WEB, session=sid, reason="session.answered-elsewhere")], **{sid: sess("initiator", "ACTIVE")}),
    ]))

    # received error surfaces
    out.append(trace("received-error-surfaced", "A received error is surfaced and changes no state.", ["§12.4"], ALICE_SELF, [
        initiator_to_active(sid)[0],
        step({"recv": msg("error", "e", BPH, sid, NOW + 1, reason="policy.rate-limited")}, [UI("error", reason="policy.rate-limited")],
             **{sid: sess("initiator", "INVITING")}),
    ]))

    # ---------------------------------------------------------------- §19.4 first contact (Phase 2)
    CAR = F.did("carol-phone")
    CAROL = F.did("carol")
    FC = {"first_contact_required": True}
    year = NOW + 31_536_000
    I1, I2, I9 = uid("intro-1", NOW), uid("intro-2", NOW + 1), uid("intro-9", NOW + 9)
    G1 = uid("grant-1", NOW + 5)

    def contacts(**k):
        base = {"allow": [], "grants_issued": [], "grants_held": [], "requests": [], "pending_sent": []}
        base.update(k)
        return base

    def fcstep(event, emit, sessions=None, contacts_=None):
        st = {"event": event, "expect": {"emit": emit, "sessions": sessions or {}}}
        if contacts_ is not None:
            st["expect"]["contacts"] = contacts_
        return st

    def fctrace(vid, desc, self_, steps, policy=FC):
        v = trace(vid, desc, ["§19.4"], self_, steps)
        v["context"]["policy"] = policy
        return v

    intro1 = {"type": "introduction", "id": I1, "from": CAR, "to": BOB, "purpose": "Met at the meetup."}
    out.append(fctrace("first-contact-responder-grant",
                       "Ungranted invite → policy.first-contact-required (no alerting); introduction lands in the requests surface; "
                       "grant admits invites by grant id or by grantee; revocation closes the door again.", BOBPH_SELF, [
        fcstep({"recv": msg("invite", "inv-a", CAR, None, NOW, to=BOB, expires_at=NOW + 30)},
               [S(type="reject", to=CAR, session=uid("inv-a"), reason="policy.first-contact-required")],
               {uid("inv-a"): sess("responder", "ENDED")}, contacts()),
        fcstep({"recv": intro1}, [UI("introduction_received", **{"from": CAROL})], {}, contacts(requests=[I1])),
        fcstep({"recv": intro1}, [{"drop": "duplicate-introduction"}], {}, contacts(requests=[I1])),
        fcstep({"local": "grant", "introduction": I1, "id": G1, "scope": ["dsip.invite"], "valid_until": year},
               [S(type="grant", to=CAROL, session=I1, id=G1, scope=["dsip.invite"], valid_until=year)], {}, contacts(grants_issued=[G1])),
        fcstep({"recv": msg("invite", "inv-b", CAR, None, NOW + 10, to=BOB, expires_at=NOW + 40, grant=G1)},
               [UI("offered")], {uid("inv-b", NOW + 10): sess("responder", "OFFERED")}),
        fcstep({"recv": msg("invite", "inv-c", CAR, None, NOW + 11, to=BOB, expires_at=NOW + 41)},
               [UI("offered")], {uid("inv-c", NOW + 11): sess("responder", "OFFERED")}),
        fcstep({"local": "revoke", "grant": G1}, [], {}, contacts()),
        fcstep({"recv": msg("invite", "inv-d", CAR, None, NOW + 12, to=BOB, expires_at=NOW + 42, grant=G1)},
               [S(type="reject", to=CAR, session=uid("inv-d", NOW + 12), reason="policy.first-contact-required")],
               {uid("inv-d", NOW + 12): sess("responder", "ENDED")}),
        fcstep({"local": "revoke", "grant": G1}, [{"refused": "unknown-grant"}]),
    ]))
    out.append(fctrace("first-contact-grant-expired", "A grant past valid_until no longer admits invites.", BOBPH_SELF, [
        fcstep({"recv": intro1}, [UI("introduction_received", **{"from": CAROL})]),
        fcstep({"local": "grant", "introduction": I1, "id": G1, "scope": ["dsip.invite"], "valid_until": NOW + 100},
               [S(type="grant", to=CAROL, session=I1, id=G1, scope=["dsip.invite"], valid_until=NOW + 100)]),
        fcstep({"recv": msg("invite", "inv-b", CAR, None, NOW + 10, to=BOB, expires_at=NOW + 40)}, [UI("offered")],
               {uid("inv-b", NOW + 10): sess("responder", "OFFERED")}),
        fcstep({"advance": 101}, []),
        fcstep({"recv": msg("invite", "inv-c", CAR, None, NOW + 101, to=BOB, expires_at=NOW + 131)},
               [S(type="reject", to=CAR, session=uid("inv-c", NOW + 101), reason="policy.first-contact-required")],
               {uid("inv-c", NOW + 101): sess("responder", "ENDED")}),
    ]))
    out.append(fctrace("first-contact-grant-scope", "A grant scoped only to dsip.subscribe does not admit invites.", BOBPH_SELF, [
        fcstep({"recv": intro1}, [UI("introduction_received", **{"from": CAROL})]),
        fcstep({"local": "grant", "introduction": I1, "id": G1, "scope": ["dsip.subscribe"], "valid_until": year},
               [S(type="grant", to=CAROL, session=I1, id=G1, scope=["dsip.subscribe"], valid_until=year)]),
        fcstep({"recv": msg("invite", "inv-b", CAR, None, NOW + 10, to=BOB, expires_at=NOW + 40, grant=G1)},
               [S(type="reject", to=CAR, session=uid("inv-b", NOW + 10), reason="policy.first-contact-required")],
               {uid("inv-b", NOW + 10): sess("responder", "ENDED")}),
    ]))
    out.append(fctrace("first-contact-reject-and-silence",
                       "Rejecting an introduction is a policy choice addressed to the introduction id; ignoring it is the default; "
                       "granting an unknown introduction is refused.", BOBPH_SELF, [
        fcstep({"recv": intro1}, [UI("introduction_received", **{"from": CAROL})], {}, contacts(requests=[I1])),
        fcstep({"local": "reject_introduction", "introduction": I1, "reason": "user.declined"},
               [S(type="reject", to=CAR, session=I1, reason="user.declined")], {}, contacts()),
        fcstep({"recv": {**intro1, "id": I2}}, [UI("introduction_received", **{"from": CAROL})], {}, contacts(requests=[I2])),
        fcstep({"advance": 604800}, [], {}, contacts(requests=[I2])),
        fcstep({"local": "grant", "introduction": I9, "id": G1, "scope": ["dsip.invite"], "valid_until": year},
               [{"refused": "unknown-introduction"}], {}, contacts(requests=[I2])),
    ]))
    out.append(fctrace("first-contact-contact-token",
                       "An introduction bearing a locally issued contact token is auto-granted; the token is single-use.", BOBPH_SELF, [
        fcstep({"local": "issue_token", "token": "tok-meetup-2026", "grant_id": G1}, []),
        fcstep({"recv": {**intro1, "contact_token": "tok-meetup-2026"}},
               [UI("introduction_received", **{"from": CAROL, "token": True}),
                S(type="grant", to=CAROL, session=I1, id=G1, scope=["dsip.invite"], valid_until=year)], {}, contacts(grants_issued=[G1])),
        fcstep({"recv": msg("invite", "inv-b", CAR, None, NOW + 10, to=BOB, expires_at=NOW + 40, grant=G1)}, [UI("offered")],
               {uid("inv-b", NOW + 10): sess("responder", "OFFERED")}),
        fcstep({"recv": {**intro1, "id": I2, "contact_token": "tok-meetup-2026"}},
               [UI("introduction_received", **{"from": CAROL})], {}, contacts(grants_issued=[G1], requests=[I2])),
    ]))
    out.append(fctrace("first-contact-allowlist", "An allow policy admits listed identities without a grant.", BOBPH_SELF, [
        fcstep({"recv": msg("invite", "inv-a", APH, None, NOW, to=BOB, expires_at=NOW + 30)}, [UI("offered")],
               {uid("inv-a"): sess("responder", "OFFERED")}),
        fcstep({"recv": msg("invite", "inv-b", CAR, None, NOW, to=BOB, expires_at=NOW + 30)},
               [S(type="reject", to=CAR, session=uid("inv-b"), reason="policy.first-contact-required")],
               {uid("inv-b"): sess("responder", "ENDED")}),
    ], policy={"first_contact_required": True, "allow": [ALICE]}))
    out.append(fctrace("first-contact-initiator",
                       "Sender side: introduce, receive the grant, then the next invite references the held grant.", ALICE_SELF, [
        fcstep({"local": "introduce", "id": I1, "to": BOB, "purpose": "Met at the meetup."},
               [S(type="introduction", to=BOB, id=I1, purpose="Met at the meetup.")], {}, contacts(pending_sent=[I1])),
        fcstep({"recv": msg("grant", "grant-x", BPH, I9, NOW + 5, scope=["dsip.invite"], valid_until=year)},
               [{"drop": "unknown-introduction"}], {}, contacts(pending_sent=[I1])),
        fcstep({"recv": msg("grant", "grant-1", BPH, I1, NOW + 5, scope=["dsip.invite"], valid_until=year)},
               [UI("granted", by=BOB)], {}, contacts(grants_held=[G1])),
        fcstep({"local": "place_call", "session": sid, "to": BOB},
               [S(type="invite", to=BOB, session=sid, grant=G1), TS("T-Establish", 15)], {sid: sess("initiator", "INVITING")}),
    ], policy={}))
    out.append(fctrace("first-contact-initiator-rejected", "Sender side: the introduction is declined.", ALICE_SELF, [
        fcstep({"local": "introduce", "id": I1, "to": BOB, "purpose": "Met at the meetup.", "contact_token": "tok-1"},
               [S(type="introduction", to=BOB, id=I1, purpose="Met at the meetup.", contact_token="tok-1")], {}, contacts(pending_sent=[I1])),
        fcstep({"recv": msg("reject", "rej-1", BPH, I1, NOW + 5, reason="user.declined")},
               [UI("introduction_rejected", reason="user.declined")], {}, contacts()),
        fcstep({"local": "place_call", "session": sid, "to": BOB},
               [S(type="invite", to=BOB, session=sid), TS("T-Establish", 15)], {sid: sess("initiator", "INVITING")}),
    ], policy={}))

    # ---------------------------------------------------------------- relay (§12.7 rules 3 and 6)
    def legs(**st):
        return st

    out.append(trace("relay-fork-answer-cancels-other-leg", "Relay forks to two legs; phone answers; initiator's cancel is delivered only to the laptop.",
                     ["§12.7"], None, [
                         rstep({"relay": "invite", "session": sid, "from": APH, "to": BOB_WEB, "legs": [BPH, BLA]},
                               [{"deliver": {"leg": BPH, "type": "invite"}}, {"deliver": {"leg": BLA, "type": "invite"}}],
                               **{sid: {"legs": {BPH: "delivered", BLA: "delivered"}, "outcome": None}}),
                         rstep({"recv": msg("progress", "p1", BPH, sid, NOW + 1, status="ringing")},
                               [{"forward": {"type": "progress", "status": "ringing", "from": BPH}}],
                               **{sid: {"legs": {BPH: "delivered", BLA: "delivered"}, "outcome": None}}),
                         rstep({"recv": msg("answer", "a1", BPH, sid, NOW + 5, answered_by="user")},
                               [{"forward": {"type": "answer", "from": BPH}}],
                               **{sid: {"legs": {BPH: "answered", BLA: "delivered"}, "outcome": "answered"}}),
                         rstep({"recv": msg("cancel", "c", APH, sid, NOW + 5, reason="session.answered-elsewhere")},
                               [{"deliver": {"leg": BLA, "type": "cancel", "reason": "session.answered-elsewhere"}}],
                               **{sid: {"legs": {BPH: "answered", BLA: "cancelled"}, "outcome": "answered"}}),
                         rstep({"recv": msg("progress", "p2", BLA, sid, NOW + 6, status="ringing")}, [{"drop": "leg-terminated"}],
                               **{sid: {"legs": {BPH: "answered", BLA: "cancelled"}, "outcome": "answered"}}),
                     ], component="relay"))
    out.append(trace("relay-attempt-outcome-most-informative", "Both legs reject; the relay forwards the most informative reason (user.declined over user.no-answer).",
                     ["§12.7"], None, [
                         rstep({"relay": "invite", "session": sid, "from": APH, "to": BOB_WEB, "legs": [BPH, BLA]},
                               [{"deliver": {"leg": BPH, "type": "invite"}}, {"deliver": {"leg": BLA, "type": "invite"}}],
                               **{sid: {"legs": {BPH: "delivered", BLA: "delivered"}, "outcome": None}}),
                         rstep({"recv": msg("reject", "r1", BPH, sid, NOW + 120, reason="user.no-answer")}, [],
                               **{sid: {"legs": {BPH: "rejected", BLA: "delivered"}, "outcome": None}}),
                         rstep({"recv": msg("reject", "r2", BLA, sid, NOW + 121, reason="user.declined")},
                               [{"forward": {"type": "reject", "reason": "user.declined", "from": BLA}}],
                               **{sid: {"legs": {BPH: "rejected", BLA: "rejected"}, "outcome": "rejected"}}),
                     ], component="relay"))
    out.append(trace("relay-attempt-outcome-busy-over-expired", "One leg busy, the other expires at the relay → endpoint.busy forwarded.", ["§12.7"], None, [
        rstep({"relay": "invite", "session": sid, "from": APH, "to": BOB_WEB, "legs": [BPH, BLA]},
              [{"deliver": {"leg": BPH, "type": "invite"}}, {"deliver": {"leg": BLA, "type": "invite"}}],
              **{sid: {"legs": {BPH: "delivered", BLA: "delivered"}, "outcome": None}}),
        rstep({"recv": msg("reject", "r1", BPH, sid, NOW + 1, reason="endpoint.busy")}, [],
              **{sid: {"legs": {BPH: "rejected", BLA: "delivered"}, "outcome": None}}),
        rstep({"relay": "leg_expired", "session": sid, "leg": BLA},
              [{"forward": {"type": "reject", "reason": "endpoint.busy", "from": BPH}}],
              **{sid: {"legs": {BPH: "rejected", BLA: "expired"}, "outcome": "rejected"}}),
    ], component="relay"))
    out.append(trace("relay-all-legs-expired", "Every leg expires without a response → endpoint.unavailable as the attempt outcome.", ["§12.7"], None, [
        rstep({"relay": "invite", "session": sid, "from": APH, "to": BOB_WEB, "legs": [BPH, BLA]},
              [{"deliver": {"leg": BPH, "type": "invite"}}, {"deliver": {"leg": BLA, "type": "invite"}}],
              **{sid: {"legs": {BPH: "delivered", BLA: "delivered"}, "outcome": None}}),
        rstep({"relay": "leg_expired", "session": sid, "leg": BPH}, [],
              **{sid: {"legs": {BPH: "expired", BLA: "delivered"}, "outcome": None}}),
        rstep({"relay": "leg_expired", "session": sid, "leg": BLA},
              [{"forward": {"type": "reject", "reason": "endpoint.unavailable", "from": BPH}}],
              **{sid: {"legs": {BPH: "expired", BLA: "expired"}, "outcome": "rejected"}}),
    ], component="relay"))
    out.append(trace("relay-user-cancel-all-legs", "Initiator abandons: cancel delivered per-leg to every live leg; later leg traffic dropped.", ["§12.7"], None, [
        rstep({"relay": "invite", "session": sid, "from": APH, "to": BOB_WEB, "legs": [BPH, BLA]},
              [{"deliver": {"leg": BPH, "type": "invite"}}, {"deliver": {"leg": BLA, "type": "invite"}}],
              **{sid: {"legs": {BPH: "delivered", BLA: "delivered"}, "outcome": None}}),
        rstep({"recv": msg("reject", "r1", BLA, sid, NOW + 1, reason="endpoint.busy")}, [],
              **{sid: {"legs": {BPH: "delivered", BLA: "rejected"}, "outcome": None}}),
        rstep({"recv": msg("cancel", "c", APH, sid, NOW + 2, reason="user.cancelled")},
              [{"deliver": {"leg": BPH, "type": "cancel", "reason": "user.cancelled"}}],
              **{sid: {"legs": {BPH: "cancelled", BLA: "rejected"}, "outcome": "cancelled"}}),
        rstep({"recv": msg("answer", "a", BPH, sid, NOW + 2, answered_by="user")}, [{"drop": "leg-terminated"}],
              **{sid: {"legs": {BPH: "cancelled", BLA: "rejected"}, "outcome": "cancelled"}}),
    ], component="relay"))
    out.append(trace("relay-late-answer-forwarded", "A second leg's answer after the first is forwarded; the initiator decides (bye already-answered).", ["§12.7"], None, [
        rstep({"relay": "invite", "session": sid, "from": APH, "to": BOB_WEB, "legs": [BPH, BLA]},
              [{"deliver": {"leg": BPH, "type": "invite"}}, {"deliver": {"leg": BLA, "type": "invite"}}],
              **{sid: {"legs": {BPH: "delivered", BLA: "delivered"}, "outcome": None}}),
        rstep({"recv": msg("answer", "a1", BPH, sid, NOW + 5, answered_by="user")}, [{"forward": {"type": "answer", "from": BPH}}],
              **{sid: {"legs": {BPH: "answered", BLA: "delivered"}, "outcome": "answered"}}),
        rstep({"recv": msg("answer", "a2", BLA, sid, NOW + 5, answered_by="user")}, [{"forward": {"type": "answer", "from": BLA}}],
              **{sid: {"legs": {BPH: "answered", BLA: "answered"}, "outcome": "answered"}}),
        rstep({"recv": msg("cancel", "c", APH, sid, NOW + 5, reason="session.answered-elsewhere")}, [],
              **{sid: {"legs": {BPH: "answered", BLA: "answered"}, "outcome": "answered"}}),
    ], component="relay"))

    # ---------------------------------------------------------------- §13.3 store-and-forward (Phase 2)
    def sf(event, emit, inbox, **attempts):
        st = rstep(event, emit, **attempts)
        st["expect"]["inbox"] = inbox
        return st
    INV = lambda label, at=NOW, ttl=30, to=BOB: msg("invite", label, APH, None, at, to=to, expires_at=at + ttl)
    sid_q = uid("queued-inv")
    out.append(trace("relay-store-and-forward-known-offline",
                     "A known identity is offline: the invite is queued (no error); binding flushes it as a tracked leg; the call proceeds.",
                     ["§13.3", "§13.2", "§12.7"], None, [
        sf({"relay": "bind", "device": BPH, "identity": BOB}, [], {}),
        sf({"relay": "unbind", "device": BPH, "identity": BOB}, [], {}),
        sf({"recv": INV("queued-inv")}, [{"queue": {"to": BOB, "type": "invite"}}], {BOB: 1}),
        sf({"advance": 5}, [], {BOB: 1}),
        sf({"relay": "bind", "device": BPH, "identity": BOB}, [{"deliver": {"leg": BPH, "type": "invite", "id": sid_q}}], {},
           **{sid_q: {"legs": {BPH: "delivered"}, "outcome": None}}),
        sf({"recv": msg("answer", "a", BPH, sid_q, NOW + 8, answered_by="user")}, [{"forward": {"type": "answer", "from": BPH}}], {},
           **{sid_q: {"legs": {BPH: "answered"}, "outcome": "answered"}}),
    ], component="relay"))
    out.append(trace("relay-queued-invite-expires",
                     "A queued invite is held only until its expires_at; after that it is dequeued silently and a late binding gets nothing.",
                     ["§13.3", "§12.9"], None, [
        sf({"relay": "bind", "device": BPH, "identity": BOB}, [], {}),
        sf({"relay": "unbind", "device": BPH, "identity": BOB}, [], {}),
        sf({"recv": INV("queued-inv")}, [{"queue": {"to": BOB, "type": "invite"}}], {BOB: 1}),
        sf({"advance": 30}, [{"dequeue": {"to": BOB, "type": "invite", "why": "expired"}}], {}),
        sf({"relay": "bind", "device": BPH, "identity": BOB}, [], {}),
    ], component="relay"))
    out.append(trace("relay-cancel-drops-queued-invite", "The initiator cancels while the invite is still queued: the queued invite is dropped.",
                     ["§13.3", "§12.11"], None, [
        sf({"relay": "bind", "device": BPH, "identity": BOB}, [], {}),
        sf({"relay": "unbind", "device": BPH, "identity": BOB}, [], {}),
        sf({"recv": INV("queued-inv")}, [{"queue": {"to": BOB, "type": "invite"}}], {BOB: 1}),
        sf({"recv": msg("cancel", "c", APH, sid_q, NOW + 3, to=BOB, reason="user.cancelled")},
           [{"dequeue": {"to": BOB, "type": "invite", "why": "cancelled"}}], {}),
        sf({"relay": "bind", "device": BPH, "identity": BOB}, [], {}),
    ], component="relay"))
    out.append(trace("relay-leg-added-mid-attempt",
                     "A second device binds while the attempt is live: it becomes a leg (§12.7 rule 3 'legs added mid-attempt'); per-leg cancel reaches it.",
                     ["§12.7", "§13.3"], None, [
        sf({"relay": "bind", "device": BPH, "identity": BOB}, [], {}),
        sf({"recv": INV("sess")}, [{"deliver": {"leg": BPH, "type": "invite"}}], {}, **{sid: {"legs": {BPH: "delivered"}, "outcome": None}}),
        sf({"relay": "bind", "device": BLA, "identity": BOB}, [{"deliver": {"leg": BLA, "type": "invite", "id": sid}}], {},
           **{sid: {"legs": {BPH: "delivered", BLA: "delivered"}, "outcome": None}}),
        sf({"recv": msg("answer", "a1", BPH, sid, NOW + 5, answered_by="user")}, [{"forward": {"type": "answer", "from": BPH}}], {},
           **{sid: {"legs": {BPH: "answered", BLA: "delivered"}, "outcome": "answered"}}),
        sf({"recv": msg("cancel", "c", APH, sid, NOW + 5, reason="session.answered-elsewhere")},
           [{"deliver": {"leg": BLA, "type": "cancel", "reason": "session.answered-elsewhere"}}], {},
           **{sid: {"legs": {BPH: "answered", BLA: "cancelled"}, "outcome": "answered"}}),
        sf({"relay": "bind", "device": "did:key:z6MkBobTablet111111111111111111111111111111", "identity": BOB}, [], {},
           **{sid: {"legs": {BPH: "answered", BLA: "cancelled"}, "outcome": "answered"}}),
    ], component="relay"))
    out.append(trace("relay-bye-queued-for-reconnecting-device",
                     "A bye addressed to a device that dropped its connection is held within the boundary and delivered on its fresh hello.",
                     ["§13.2", "§13.3"], None, [
        sf({"relay": "bind", "device": BPH, "identity": BOB}, [], {}),
        sf({"relay": "unbind", "device": BPH, "identity": BOB}, [], {}),
        sf({"recv": msg("bye", "b", APH, sid, NOW, to=BPH, reason="user.hangup", expires_at=NOW + 30)},
           [{"queue": {"to": BPH, "type": "bye"}}], {BPH: 1}),
        sf({"relay": "bind", "device": BPH, "identity": BOB}, [{"deliver": {"leg": BPH, "type": "bye", "id": uid("b")}}], {}),
    ], component="relay"))
    out.append(trace("relay-retention-cap", "The relay's offline_retention_s caps how long an envelope is held even if expires_at is later.",
                     ["§13.3"], None, [
        sf({"relay": "bind", "device": BPH, "identity": BOB}, [], {}),
        sf({"relay": "unbind", "device": BPH, "identity": BOB}, [], {}),
        sf({"recv": {"type": "introduction", "id": uid("intro-long"), "from": F.did("carol-phone"), "to": BOB, "purpose": "hi", "expires_at": NOW + 604800}},
           [{"queue": {"to": BOB, "type": "introduction"}}], {BOB: 1}),
        sf({"advance": 3600}, [{"dequeue": {"to": BOB, "type": "introduction", "why": "expired"}}], {}),
    ], component="relay"))
    out[-1]["context"]["offline_retention_s"] = 3600

    upd_id = uid("sf-upd", NOW + 10)
    out.append(trace("relay-post-answer-traffic-routed-by-to",
                     "After the answer, update/info/bye and update replies are not attempt-scoped: the relay routes them by `to` "
                     "(device-addressed), queueing for a device that has dropped its connection.", ["§13.2", "§12.8", "§13.3"], None, [
        sf({"relay": "bind", "device": BPH, "identity": BOB}, [], {}),
        sf({"relay": "bind", "device": APH, "identity": ALICE}, [], {}),
        sf({"recv": INV("sess")}, [{"deliver": {"leg": BPH, "type": "invite"}}], {}, **{sid: {"legs": {BPH: "delivered"}, "outcome": None}}),
        sf({"recv": msg("answer", "a1", BPH, sid, NOW + 5, answered_by="user")}, [{"forward": {"type": "answer", "from": BPH}}], {},
           **{sid: {"legs": {BPH: "answered"}, "outcome": "answered"}}),
        sf({"recv": msg("update", "sf-upd", BPH, sid, NOW + 10, to=APH)}, [{"deliver": {"leg": APH, "type": "update", "id": upd_id}}], {}),
        sf({"recv": msg("answer", "ua", APH, sid, NOW + 11, to=BPH, answered_by="user", in_reply_to=upd_id)},
           [{"deliver": {"leg": BPH, "type": "answer", "id": uid("ua", NOW + 11)}}], {}),
        sf({"recv": msg("info", "i", APH, sid, NOW + 12, to=BPH, about="transport:webrtc")},
           [{"deliver": {"leg": BPH, "type": "info", "id": uid("i", NOW + 12)}}], {}),
        sf({"relay": "unbind", "device": BPH, "identity": BOB}, [], {}),
        sf({"recv": msg("bye", "b", APH, sid, NOW + 20, to=BPH, reason="user.hangup", expires_at=NOW + 50)},
           [{"queue": {"to": BPH, "type": "bye"}}], {BPH: 1}),
        sf({"relay": "bind", "device": BPH, "identity": BOB}, [{"deliver": {"leg": BPH, "type": "bye", "id": uid("b", NOW + 20)}}], {}),
    ], component="relay"))

    # ---------------------------------------------------------------- §22 / §9.3 broadcast (Phase 3)
    STREAM = BOB + ":radio:main"
    AUTH = "did:key:z6MkAuthorityRelay11111111111111111111111111"
    VARS = [{"id": "main-opus", "media": ["audio"], "codec": "codec:audio/opus", "transport": "transport:webrtc", "uri": "wss://live.example/main"},
            {"id": "main-aac-hls", "media": ["audio"], "codec": "codec:audio/aac", "transport": "transport:hls", "uri": "https://live.example/main.m3u8"}]
    PUB1, PUB2 = uid("pub-1", NOW), uid("pub-2", NOW + 100)
    SUB1, SUB2, SUB3 = uid("sub-1", NOW + 1), uid("sub-2", NOW + 2), uid("sub-3", NOW + 3)

    def bstep(event, emit, **snaps):
        return {"event": event, "expect": {"emit": emit, **snaps}}

    def btrace(vid, desc, refs, steps, component="authority"):
        v = trace(vid, desc, refs, None, steps, component=component)
        v["context"]["identities"] = IDENTITIES
        return v

    def publish(label, at=NOW, state="live", ttl=300, publisher=BOB, frm=BPH, stream=STREAM, policy=None):
        m = {"type": "publish", "id": uid(label, at), "from": frm, "publisher": publisher, "stream_id": stream, "state": state,
             "variants": VARS, "expires_at": at + ttl}
        if policy is not None:
            m["policy"] = policy
        return m

    def subscribe(label, frm, target, events, expires_in, at=NOW, capability=None):
        m = {"type": "subscribe", "id": uid(label, at), "from": frm, "to": AUTH, "target": target, "events": events, "expires_in": expires_in}
        if capability:
            m["capability"] = capability
        return m

    def notify(to, sub, seq, state, body, reason=None):
        d = {"type": "notify", "to": to, "subscription": sub, "seq": seq, "state": state}
        if reason:
            d["reason"] = reason
        d["body"] = body
        return {"send": d}

    live = {"event": "publication", "state": "live", "publication": PUB1}
    subsnap = lambda sid, who, target, events, seq, exp: {sid: {"subscriber": who, "target": target, "events": events, "seq": seq, "expires_at": exp}}
    pubsnap = lambda state, pid=PUB1: {STREAM: {"publication": pid, "publisher": BOB, "state": state}}

    out.append(btrace("broadcast-authority-publish-subscribe-notify",
                      "Publisher's relay holds the signed record; a subscriber's first notify carries current state; state changes, "
                      "unpublish and subscription expiry are seq-ordered notifies; lapse ends with session.expired.", ["§22.1", "§9.3"], [
        bstep({"local": "policy", "target": STREAM, "mode": "public"}, []),
        bstep({"recv": publish("pub-1")}, [{"publication": {"stream": STREAM, "state": "live"}}], publications=pubsnap("live")),
        bstep({"recv": subscribe("sub-1", APH, STREAM, ["publication"], 600, NOW + 1)},
              [notify(APH, SUB1, 1, "active", live)], subscriptions=subsnap(SUB1, ALICE, STREAM, ["publication"], 1, NOW + 600)),
        bstep({"recv": publish("pub-2", NOW + 100, state="ended")},
              [{"publication": {"stream": STREAM, "state": "ended"}}, notify(APH, SUB1, 2, "active", {"event": "publication", "state": "ended", "publication": PUB2})],
              publications=pubsnap("ended", PUB2)),
        bstep({"recv": {"type": "unpublish", "id": uid("unpub"), "from": BPH, "publisher": BOB, "stream_id": STREAM, "publication": PUB2}},
              [{"publication": {"stream": STREAM, "state": "withdrawn"}}, notify(APH, SUB1, 3, "active", {"event": "publication", "state": "withdrawn", "publication": PUB2})],
              publications=pubsnap("withdrawn", PUB2)),
        bstep({"advance": 600}, [notify(APH, SUB1, 4, "terminated", {"event": "publication", "state": "withdrawn", "publication": PUB2}, "session.expired")],
              subscriptions={}),
    ]))
    out.append(btrace("broadcast-authority-anti-enumeration",
                      "Unauthorized and nonexistent targets get the identical reject policy.blocked; an allowlisted subscriber and a capability token get in.",
                      ["§9.3"], [
        bstep({"local": "policy", "target": STREAM, "mode": "allow", "allow": [ALICE]}, []),
        bstep({"recv": publish("pub-1")}, [{"publication": {"stream": STREAM, "state": "live"}}]),
        bstep({"recv": subscribe("sub-1", F.did("carol-phone"), STREAM, ["publication"], 600, NOW + 1)},
              [S(type="reject", to=F.did("carol-phone"), session=SUB1, reason="policy.blocked")], subscriptions={}),
        bstep({"recv": subscribe("sub-2", APH, BOB + ":radio:nope", ["publication"], 600, NOW + 2)},
              [S(type="reject", to=APH, session=SUB2, reason="policy.blocked")], subscriptions={}),
        bstep({"recv": subscribe("sub-3", APH, STREAM, ["publication"], 600, NOW + 3)},
              [notify(APH, SUB3, 1, "active", live)], subscriptions=subsnap(SUB3, ALICE, STREAM, ["publication"], 1, NOW + 600)),
        bstep({"local": "issue_capability", "token": "follow-7f3a", "target": STREAM}, []),
        bstep({"recv": subscribe("sub-4", F.did("carol-phone"), STREAM, ["publication"], 600, NOW + 4, capability="follow-7f3a")},
              [notify(F.did("carol-phone"), uid("sub-4", NOW + 4), 1, "active", live)]),
        bstep({"recv": subscribe("sub-5", F.did("carol-phone"), STREAM, ["publication"], 600, NOW + 5, capability="wrong")},
              [S(type="reject", to=F.did("carol-phone"), session=uid("sub-5", NOW + 5), reason="policy.blocked")]),
    ]))
    out.append(btrace("broadcast-authority-caps-renewal-terminate",
                      "Lifetimes never exceed the per-event cap (an over-cap request is refused earlier by the stateless check, semantic/subscribe-presence-over-cap); renewal replaces the prior subscription; expires_in 0 terminates.",
                      ["§9.3"], [
        bstep({"local": "policy", "target": BOB, "mode": "public"}, []),
        bstep({"local": "policy", "target": STREAM, "mode": "public"}, []),
        bstep({"recv": publish("pub-1")}, [{"publication": {"stream": STREAM, "state": "live"}}]),
        bstep({"recv": subscribe("sub-1", APH, BOB, ["presence"], 3600, NOW + 1)},
              [notify(APH, SUB1, 1, "active", {"event": "presence", "state": "offline"})],
              subscriptions=subsnap(SUB1, ALICE, BOB, ["presence"], 1, NOW + 3600)),
        bstep({"recv": subscribe("sub-2", APH, STREAM, ["publication"], 86400, NOW + 2)},
              [notify(APH, SUB2, 1, "active", live)],
              subscriptions={**subsnap(SUB1, ALICE, BOB, ["presence"], 1, NOW + 3600), **subsnap(SUB2, ALICE, STREAM, ["publication"], 1, NOW + 86400)}),
        bstep({"recv": subscribe("sub-3", APH, STREAM, ["publication"], 600, NOW + 3)},
              [{"subscription": {"id": SUB2, "state": "replaced"}}, notify(APH, SUB3, 1, "active", live)],
              subscriptions={**subsnap(SUB1, ALICE, BOB, ["presence"], 1, NOW + 3600), **subsnap(SUB3, ALICE, STREAM, ["publication"], 1, NOW + 600)}),
        bstep({"recv": subscribe("sub-4", APH, STREAM, ["publication"], 0, NOW + 4)},
              [{"subscription": {"id": SUB3, "state": "terminated"}}], subscriptions=subsnap(SUB1, ALICE, BOB, ["presence"], 1, NOW + 3600)),
        bstep({"recv": subscribe("sub-5", APH, STREAM, ["publication"], 0, NOW + 5)}, [{"drop": "no-matching-subscription"}]),
    ]))
    out.append(btrace("broadcast-authority-publisher-binding",
                      "Only the verified publisher (or its delegate) may publish or withdraw its streams; stream_id is namespaced under the publisher; older records never replace newer ones.",
                      ["§22.1", "§8.1", "§8.3"], [
        bstep({"recv": publish("pub-x", publisher=ALICE, stream=ALICE + ":radio")}, [{"drop": "publisher-mismatch"}], publications={}),
        bstep({"recv": publish("pub-y", stream="did:web:wxyz.com:radio")}, [{"drop": "stream-id-namespace"}], publications={}),
        bstep({"recv": publish("pub-2", NOW + 100)}, [{"publication": {"stream": STREAM, "state": "live"}}], publications=pubsnap("live", PUB2)),
        bstep({"recv": publish("pub-1")}, [{"drop": "stale-publication"}], publications=pubsnap("live", PUB2)),
        bstep({"recv": {"type": "unpublish", "id": uid("unpub"), "from": F.did("carol-phone"), "publisher": BOB, "stream_id": STREAM, "publication": PUB2}},
              [{"drop": "publisher-mismatch"}], publications=pubsnap("live", PUB2)),
        bstep({"recv": {"type": "unpublish", "id": uid("unpub2"), "from": BPH, "publisher": BOB, "stream_id": STREAM, "publication": PUB1}},
              [{"drop": "unknown-publication"}], publications=pubsnap("live", PUB2)),
        bstep({"recv": {"type": "unpublish", "id": uid("unpub3"), "from": F.did("bob-laptop"), "publisher": BOB, "stream_id": STREAM, "publication": PUB2}},
              [{"publication": {"stream": STREAM, "state": "withdrawn"}}], publications=pubsnap("withdrawn", PUB2)),
    ]))
    prov = lambda label, processor=CAROL, frm=F.did("carol-phone"), pub=PUB1, inp="main-opus", op="transcode": {
        "type": "provenance", "id": uid(label, NOW + 10), "from": frm, "original_stream": STREAM, "original_publication": pub,
        "processor": processor, "operation": op, "input_variant": inp, "output_variant": "main-aac-hls"}
    out.append(btrace("broadcast-authority-provenance",
                      "A processor's statement is attached to the record (never replacing the publisher) and subscribers are notified; mismatched statements are dropped; a replacing record starts with no statements.",
                      ["§22.3"], [
        bstep({"local": "policy", "target": STREAM, "mode": "public"}, []),
        bstep({"recv": publish("pub-1")}, [{"publication": {"stream": STREAM, "state": "live"}}]),
        bstep({"recv": subscribe("sub-1", APH, STREAM, ["publication"], 600, NOW + 1)}, [notify(APH, SUB1, 1, "active", live)]),
        bstep({"recv": prov("prov-1")}, [{"provenance": {"stream": STREAM, "processor": CAROL}},
                                         notify(APH, SUB1, 2, "active", {**live, "provenance": [CAROL]})]),
        bstep({"recv": prov("prov-2", pub=PUB2)}, [{"drop": "provenance-unknown-publication"}]),
        bstep({"recv": prov("prov-3", processor=ALICE)}, [{"drop": "provenance-processor-mismatch"}]),
        bstep({"recv": prov("prov-4", inp="nope")}, [{"drop": "provenance-variant-unknown"}]),
        bstep({"recv": publish("pub-2", NOW + 100, state="ended")},
              [{"publication": {"stream": STREAM, "state": "ended"}},
               notify(APH, SUB1, 3, "active", {"event": "publication", "state": "ended", "publication": PUB2})]),
    ]))
    out.append(btrace("broadcast-authority-presence",
                      "Presence subscriptions (§9.3 event class) follow the target's device bindings; unknown targets get the uniform reject.",
                      ["§9.3", "§9.2"], [
        bstep({"local": "policy", "target": BOB, "mode": "public"}, []),
        bstep({"recv": subscribe("sub-1", APH, BOB, ["presence"], 600, NOW + 1)},
              [notify(APH, SUB1, 1, "active", {"event": "presence", "state": "offline"})]),
        bstep({"relay": "bind", "device": BPH, "identity": BOB}, [notify(APH, SUB1, 2, "active", {"event": "presence", "state": "available"})]),
        bstep({"relay": "unbind", "device": BPH, "identity": BOB}, [notify(APH, SUB1, 3, "active", {"event": "presence", "state": "offline"})]),
        bstep({"recv": subscribe("sub-2", APH, "did:key:z6MkNobodyHereAtAll11111111111111111111111111", ["presence"], 600, NOW + 2)},
              [S(type="reject", to=APH, session=SUB2, reason="policy.blocked")]),
    ]))
    out.append(btrace("broadcast-authority-publication-expiry",
                      "A live record past its expires_at is marked expired and subscribers are told.", ["§22.1", "§8.3"], [
        bstep({"local": "policy", "target": STREAM, "mode": "public"}, []),
        bstep({"recv": publish("pub-1")}, [{"publication": {"stream": STREAM, "state": "live"}}]),
        bstep({"recv": subscribe("sub-1", APH, STREAM, ["publication"], 600, NOW + 1)}, [notify(APH, SUB1, 1, "active", live)]),
        bstep({"advance": 300}, [{"publication": {"stream": STREAM, "state": "expired"}},
                                 notify(APH, SUB1, 2, "active", {"event": "publication", "state": "expired", "publication": PUB1})],
              publications=pubsnap("expired")),
    ]))
    # subscriber side
    ntf = lambda sub, seq, state, body=None, reason=None: {k: v for k, v in {"type": "notify", "id": uid(f"n{seq}{sub[-4:]}", NOW + seq), "from": AUTH,
                                                                            "subscription": sub, "seq": seq, "state": state, "reason": reason,
                                                                            "body": body or {"event": "publication", "state": "live"}}.items() if v is not None}
    out.append(btrace("broadcast-subscriber-seq-and-terminal",
                      "Subscriber discards lower-than-seen seq, treats terminated as final, ignores unknown subscriptions.", ["§9.3"], [
        bstep({"local": "subscribe", "id": SUB1, "to": AUTH, "target": STREAM, "events": ["publication"], "expires_in": 600},
              [{"send": {"type": "subscribe", "to": AUTH, "id": SUB1, "target": STREAM, "events": ["publication"], "expires_in": 600}}],
              subscriptions={SUB1: {"target": STREAM, "state": "pending", "seq": 0}}),
        bstep({"recv": ntf(SUB1, 1, "active")}, [UI("notify", event="publication", state="live")],
              subscriptions={SUB1: {"target": STREAM, "state": "active", "seq": 1}}),
        bstep({"recv": ntf(SUB1, 1, "active")}, [{"drop": "stale-seq"}]),
        bstep({"recv": ntf(SUB1, 3, "active", {"event": "publication", "state": "ended"})}, [UI("notify", event="publication", state="ended")],
              subscriptions={SUB1: {"target": STREAM, "state": "active", "seq": 3}}),
        bstep({"recv": ntf(SUB1, 2, "active")}, [{"drop": "stale-seq"}]),
        bstep({"recv": ntf(SUB1, 4, "terminated", reason="session.expired")}, [UI("subscription_terminated", reason="session.expired")],
              subscriptions={SUB1: {"target": STREAM, "state": "terminated", "seq": 4}}),
        bstep({"recv": ntf(SUB1, 5, "active")}, [{"drop": "terminated-subscription"}]),
        bstep({"recv": ntf(SUB2, 1, "active")}, [{"drop": "unknown-subscription"}]),
    ], component="subscriber"))
    out.append(btrace("broadcast-subscriber-rejected-and-lapse",
                      "A rejected subscription surfaces its reason; an active one that is not renewed lapses locally.", ["§9.3"], [
        bstep({"local": "subscribe", "id": SUB1, "to": AUTH, "target": STREAM, "events": ["publication"], "expires_in": 600},
              [{"send": {"type": "subscribe", "to": AUTH, "id": SUB1, "target": STREAM, "events": ["publication"], "expires_in": 600}}]),
        bstep({"recv": {"type": "reject", "id": uid("rj"), "from": AUTH, "session": SUB1, "reason": "policy.blocked"}},
              [UI("subscription_rejected", reason="policy.blocked")], subscriptions={SUB1: {"target": STREAM, "state": "rejected", "seq": 0}}),
        bstep({"local": "subscribe", "id": SUB2, "to": AUTH, "target": BOB, "events": ["presence"], "expires_in": 60},
              [{"send": {"type": "subscribe", "to": AUTH, "id": SUB2, "target": BOB, "events": ["presence"], "expires_in": 60}}]),
        bstep({"recv": ntf(SUB2, 1, "active", {"event": "presence", "state": "available"})}, [UI("notify", event="presence", state="available")]),
        bstep({"advance": 60}, [UI("subscription_lapsed", subscription=SUB2)],
              subscriptions={SUB1: {"target": STREAM, "state": "rejected", "seq": 0}, SUB2: {"target": BOB, "state": "lapsed", "seq": 1}}),
    ], component="subscriber"))

    UNKNOWN = "did:key:z6MkNobodyHereAtAll11111111111111111111111111"
    def rinbox(event, emit, inbox, **attempts):
        st = rstep(event, emit, **attempts)
        st["expect"]["inbox"] = inbox
        return st
    out.append(trace("relay-introduction-anti-enumeration",
                     "Introductions to an unknown identity and to an offline identity are treated identically (queued, no error); "
                     "session traffic to an unknown identity still gets transport.unknown-recipient; binding flushes the inbox.",
                     ["§19.4", "§13.2", "§13.3"], None, [
        rinbox({"recv": {"type": "introduction", "id": I1, "from": CAR, "to": UNKNOWN, "purpose": "hi"}},
               [{"queue": {"to": UNKNOWN, "type": "introduction"}}], {UNKNOWN: 1}),
        rinbox({"recv": {"type": "introduction", "id": I2, "from": CAR, "to": BOB, "purpose": "hi"}},
               [{"queue": {"to": BOB, "type": "introduction"}}], {BOB: 1, UNKNOWN: 1}),
        rinbox({"relay": "bind", "device": BPH, "identity": BOB}, [{"deliver": {"leg": BPH, "type": "introduction", "id": I2}}], {UNKNOWN: 1}),
        rinbox({"recv": {"type": "introduction", "id": I9, "from": CAR, "to": BOB, "purpose": "hi again"}},
               [{"deliver": {"leg": BPH, "type": "introduction"}}], {UNKNOWN: 1}),
        rinbox({"recv": msg("invite", "inv-u", APH, None, NOW, to=UNKNOWN)},
               [{"send": {"type": "error", "to": APH, "reason": "transport.unknown-recipient", "in_reply_to": uid("inv-u")}}], {UNKNOWN: 1}),
        rinbox({"recv": msg("invite", "sess", APH, None, NOW, to=BOB)},
               [{"deliver": {"leg": BPH, "type": "invite"}}], {UNKNOWN: 1}, **{sid: {"legs": {BPH: "delivered"}, "outcome": None}}),
        rinbox({"relay": "unbind", "device": BPH, "identity": BOB}, [], {UNKNOWN: 1}),
        rinbox({"recv": {"type": "introduction", "id": uid("intro-3"), "from": CAR, "to": BOB, "purpose": "offline again"}},
               [{"queue": {"to": BOB, "type": "introduction"}}], {BOB: 1, UNKNOWN: 1}),
    ], component="relay"))
    return out
