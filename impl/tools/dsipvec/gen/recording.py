"""`recording/` vectors — Recording Profile draft (C§4–C§6; spec-gap 107). Expectations are written out by hand."""
from __future__ import annotations

from .common import vector

REC = "did:web:rec.acme.example"
REC2 = "did:web:rec2.acme.example"
BOB = "did:web:acme.example:bob"
CAROL = "did:web:carol.example"
SID = "01J9ZRECRD0000000000000001"
D = "policy.recording-declined"


def rv(vid, desc, refs, inp, expect, ctx=None):
    return vector(f"recording/{vid}", "recording", desc, refs, ctx or {}, inp, expect)


def trace(vid, desc, ctx, steps, refs=("C§4",)):
    return rv(vid, desc, list(refs), {"steps": [{"event": e} for e, _ in steps]}, [x for _, x in steps], ctx)


def decl(state="on", recorder=REC, purpose="compliance"):
    d = {"state": state, "recorder": recorder}
    if purpose is not None:
        d["purpose"] = purpose
    return d


def got(t, rec=None):
    r = {"type": t}
    if rec is not None:
        r["recording"] = rec
    return {"received": r}


def snap(emit, disclosure=None, pending=False, accepted=(), ended=None):
    return {"emit": emit, "disclosure": disclosure, "pending": pending, "hold_media": pending and ended is None,
            "accepted": sorted(accepted), "ended": ended}


def render(d):
    return {"render": dict(d)}


ACCEPT, DECLINE, ANSWER = {"local": "accept"}, {"local": "decline"}, {"local": "answer"}


def consent_vectors() -> list[dict]:
    out = []
    callee, caller = {"role": "callee", "accept": "ask"}, {"role": "caller", "accept": "ask"}
    on = decl()
    out.append(trace("callee-must-accept-before-answering", "An invite declaring recording: the callee cannot answer until it accepts.",
                     callee, [
                         (got("invite", on), snap([render(on)], on, True)),
                         (ANSWER, snap([{"blocked": "awaiting-acceptance"}], on, True)),
                         (ACCEPT, snap([{"accepted": {"recorder": REC, "by": "user"}}], on, False, [REC])),
                         (ANSWER, snap([{"send": {"type": "answer"}}], on, False, [REC])),
                     ]))
    out.append(trace("callee-declines-with-reject", "The callee declines before answering: a reject with policy.recording-declined.",
                     callee, [
                         (got("invite", on), snap([render(on)], on, True)),
                         (DECLINE, snap([{"send": {"type": "reject", "reason": D}}], on, False, ended=D)),
                         (ANSWER, snap([], on, False, ended=D)),
                         (got("update", decl(recorder=REC2)), snap([], on, False, ended=D)),
                     ]))
    out.append(trace("caller-holds-media-after-recorded-answer", "The callee records: its answer declares it, and the caller holds its "
                     "media until it accepts.", caller, [
                         (got("answer", on), snap([render(on)], on, True)),
                         (ACCEPT, snap([{"accepted": {"recorder": REC, "by": "user"}}], on, False, [REC])),
                     ]))
    out.append(trace("caller-declines-with-bye", "A caller declining after the answer ends the session with bye.", caller, [
        (got("answer", on), snap([render(on)], on, True)),
        (DECLINE, snap([{"send": {"type": "bye", "reason": D}}], on, False, ended=D)),
    ]))
    out.append(trace("no-declaration-no-prompt", "No declaration: nothing to render, nothing held, answering proceeds.", callee, [
        (got("invite"), snap([])),
        (ANSWER, snap([{"send": {"type": "answer"}}])),
        (DECLINE, snap([])),
    ]))
    out.append(trace("update-starts-recording-mid-call", "Recording begun mid-call by update holds media until acceptance; ending "
                     "it releases the disclosure.", caller, [
                         (got("answer"), snap([])),
                         (got("update", on), snap([render(on)], on, True)),
                         (ACCEPT, snap([{"accepted": {"recorder": REC, "by": "user"}}], on, False, [REC])),
                         (got("update", {"state": "off"}), snap([{"render": {"state": "off", "recorder": REC}}], None, False, [REC])),
                     ]))
    pa = decl("paused")
    out.append(trace("pause-and-resume-same-recorder", "Paused holds nothing; resuming with the same recorder needs no new acceptance.",
                     caller, [
                         (got("answer", on), snap([render(on)], on, True)),
                         (ACCEPT, snap([{"accepted": {"recorder": REC, "by": "user"}}], on, False, [REC])),
                         (got("update", pa), snap([render(pa)], pa, False, [REC])),
                         (got("update", on), snap([render(on)], on, False, [REC])),
                     ]))
    out.append(trace("paused-before-acceptance", "A pause before acceptance releases the hold; resuming asks again.", caller, [
        (got("answer", on), snap([render(on)], on, True)),
        (got("update", pa), snap([render(pa)], pa, False)),
        (ACCEPT, snap([], pa, False)),
        (got("update", on), snap([render(on)], on, True)),
    ]))
    r2 = decl(recorder=REC2)
    out.append(trace("new-recorder-asks-again", "Acceptance is per recorder: a different recorder holds media again.", caller, [
        (got("answer", on), snap([render(on)], on, True)),
        (ACCEPT, snap([{"accepted": {"recorder": REC, "by": "user"}}], on, False, [REC])),
        (got("update", r2), snap([render(r2)], r2, True, [REC])),
        (ACCEPT, snap([{"accepted": {"recorder": REC2, "by": "user"}}], r2, False, [REC, REC2])),
    ]))
    out.append(trace("return-to-accepted-recorder-releases-hold", "A new recorder is pending; returning to the accepted one "
                     "releases the hold without asking.", caller, [
                         (got("answer", on), snap([render(on)], on, True)),
                         (ACCEPT, snap([{"accepted": {"recorder": REC, "by": "user"}}], on, False, [REC])),
                         (got("update", r2), snap([render(r2)], r2, True, [REC])),
                         (got("update", on), snap([render(on)], on, False, [REC])),
                         (ACCEPT, snap([], on, False, [REC])),
                     ]))
    out.append(trace("caller-answer-does-nothing", "A caller has nothing to answer: local answer emits nothing.", caller, [
        (got("answer", on), snap([render(on)], on, True)),
        (ANSWER, snap([], on, True)),
    ]))
    out.append(trace("same-declaration-renders-once", "An update repeating the declaration renders nothing new.", caller, [
        (got("answer", on), snap([render(on)], on, True)),
        (got("update", on), snap([], on, True)),
    ]))
    pq = decl(purpose="quality")
    out.append(trace("purpose-change-renders", "A changed purpose is rendered; the recorder is still accepted.", caller, [
        (got("answer", on), snap([render(on)], on, True)),
        (ACCEPT, snap([{"accepted": {"recorder": REC, "by": "user"}}], on, False, [REC])),
        (got("update", pq), snap([render(pq)], pq, False, [REC])),
    ]))
    np = decl(purpose=None)
    out.append(trace("purpose-absent", "Without a purpose the render carries none.", callee, [
        (got("invite", np), snap([render(np)], np, True)),
    ]))
    out.append(trace("policy-always-accepts", "A standing policy of always accepting: rendered, accepted, nothing held.",
                     {"role": "callee", "accept": "always"}, [
                         (got("invite", on), snap([render(on), {"accepted": {"recorder": REC, "by": "policy"}}], on, False, [REC])),
                         (ANSWER, snap([{"send": {"type": "answer"}}], on, False, [REC])),
                     ]))
    out.append(trace("policy-never-declines", "A standing policy of never (or policy.recording forbidden): rendered and declined at once.",
                     {"role": "callee", "accept": "never"}, [
                         (got("invite", on), snap([render(on), {"send": {"type": "reject", "reason": D}}], on, False, ended=D)),
                     ]))
    out.append(trace("policy-never-mid-call-bye", "Never, mid-call: the session ends with bye.", {"role": "caller", "accept": "never"}, [
        (got("answer"), snap([])),
        (got("update", on), snap([render(on), {"send": {"type": "bye", "reason": D}}], on, False, ended=D)),
    ]))
    out.append(trace("callee-answered-then-declines-bye", "A callee that has answered declines with bye, not reject.", callee, [
        (got("invite"), snap([])),
        (ANSWER, snap([{"send": {"type": "answer"}}])),
        (got("update", on), snap([render(on)], on, True)),
        (DECLINE, snap([{"send": {"type": "bye", "reason": D}}], on, False, ended=D)),
    ]))
    unk = decl("streaming")
    out.append(trace("unregistered-state-reads-as-on", "An unregistered state is rendered as given and treated as on.", callee, [
        (got("invite", unk), snap([render(unk)], unk, True)),
    ]))
    out.append(trace("decline-after-accepting", "A party may decline at any time, even after accepting.", caller, [
        (got("answer", on), snap([render(on)], on, True)),
        (ACCEPT, snap([{"accepted": {"recorder": REC, "by": "user"}}], on, False, [REC])),
        (DECLINE, snap([{"send": {"type": "bye", "reason": D}}], on, False, [REC], ended=D)),
    ]))
    out.append(trace("off-without-disclosure-is-silent", "An off declaration with nothing disclosed renders nothing.", caller, [
        (got("answer", {"state": "off"}), snap([])),
    ]))
    return out


def conversation_vectors() -> list[dict]:
    out = []
    R = ["C§5"]
    alice = {"device": "did:key:z6MkAlice1", "subject": "did:web:alice.example", "capabilities": ["dsip.signaling", "dsip.messaging"]}
    bob = {"device": "did:key:z6MkBob1", "subject": BOB, "capabilities": ["dsip.signaling", "dsip.messaging"]}
    bobrec = {"device": "did:key:z6MkBobRec", "subject": BOB, "capabilities": ["dsip.signaling", "dsip.messaging", "dsip.record"]}
    rec2 = {"device": "did:key:z6MkAcmeRec", "subject": "did:web:acme.example", "capabilities": ["dsip.messaging", "dsip.record"]}

    def cv(vid, desc, inp, want):
        out.append(rv(f"conversation-{vid}", desc, R, {"check": "conversation", **inp}, want))
    cv("not-recorded", "No leaf carries dsip.record.", {"leaves": [alice, bob], "accepted": []},
       {"recorded": False, "recorders": [], "may_send": True})
    cv("recorded-not-accepted", "A recorder device of Bob's: the conversation is recorded and Alice may not send yet.",
       {"leaves": [alice, bob, bobrec], "accepted": []},
       {"recorded": True, "recorders": [{"device": "did:key:z6MkBobRec", "subject": BOB}], "may_send": False})
    cv("recorded-accepted", "Once accepted, Alice may send.", {"leaves": [alice, bob, bobrec], "accepted": ["did:key:z6MkBobRec"]},
       {"recorded": True, "recorders": [{"device": "did:key:z6MkBobRec", "subject": BOB}], "may_send": True})
    cv("second-recorder-asks-again", "Acceptance is per set of recorder devices: a new recorder blocks sending again.",
       {"leaves": [alice, bob, bobrec, rec2], "accepted": ["did:key:z6MkBobRec"]},
       {"recorded": True, "recorders": [{"device": "did:key:z6MkAcmeRec", "subject": "did:web:acme.example"},
                                        {"device": "did:key:z6MkBobRec", "subject": BOB}], "may_send": False})
    cv("recorder-content-not-rendered", "Content from the recorder leaf is not rendered: a recorder is receive-only.",
       {"leaves": [alice, bob, bobrec], "accepted": ["did:key:z6MkBobRec"], "sender": "did:key:z6MkBobRec"},
       {"recorded": True, "recorders": [{"device": "did:key:z6MkBobRec", "subject": BOB}], "may_send": True, "render_sender": False})
    cv("member-content-rendered", "Bob's own device speaks for Bob.",
       {"leaves": [alice, bob, bobrec], "accepted": [], "sender": "did:key:z6MkBob1"},
       {"recorded": True, "recorders": [{"device": "did:key:z6MkBobRec", "subject": BOB}], "may_send": False, "render_sender": True})
    cv("unknown-sender-not-rendered", "A sender that is no leaf is unauthenticated.",
       {"leaves": [alice, bob], "accepted": [], "sender": "did:key:z6MkStranger"},
       {"recorded": False, "recorders": [], "may_send": True, "render_sender": False})
    return out


def session_vectors() -> list[dict]:
    out = []
    R = ["C§6"]
    declared = {"session": SID, "state": "on", "recorder": REC}
    recorder = {"identity": REC, "capabilities": ["dsip.signaling", "dsip.media.interactive", "dsip.record"]}
    rs = {"of": SID, "participants": [{"identity": BOB, "role": "self"}, {"identity": CAROL, "role": "peer"}],
          "streams": [{"media": 0, "participant": BOB}, {"media": 1, "participant": CAROL}]}
    media = [{"type": "audio", "direction": "sendonly"}, {"type": "audio", "direction": "sendonly"}]

    def sv(vid, desc, d=declared, r=recorder, m=media, s=rs, want=None):
        out.append(rv(f"session-{vid}", desc, R, {"check": "recording-session", "declared": d, "recorder": r,
                                                    "offer": {"media": m, "recording_session": s}}, want))
    sv("ok", "Bob's side and Carol's, each its own sendonly stream, to the declared recorder.", want={"ok": True})
    sv("not-declared", "Nothing declared in the recorded session: no recording session.", d={"session": SID, "state": "off"},
       want={"refused": "not-declared"})
    sv("not-declared-absent", "An absent declaration is off.", d={"session": SID}, want={"refused": "not-declared"})
    sv("paused-is-declared", "A paused declaration is still a declaration (the leg's media is then inactive).",
       d={**declared, "state": "paused"}, want={"ok": True})
    sv("recorder-mismatch", "The recorder answering is not the one declared.", r={**recorder, "identity": REC2},
       want={"refused": "recorder-mismatch"})
    sv("missing-capability", "The recorder's delegation lacks dsip.record.",
       r={**recorder, "capabilities": ["dsip.signaling", "dsip.media.interactive"]}, want={"refused": "missing-capability"})
    sv("wrong-session", "The metadata names another session.", s={**rs, "of": "01J9ZRECRD0000000000000002"},
       want={"refused": "wrong-session"})
    sv("stream-out-of-range", "A stream names a media section that is not offered.",
       s={**rs, "streams": [{"media": 2, "participant": BOB}]}, want={"refused": "bad-stream-map"})
    sv("stream-duplicate", "Two streams name the same media section.",
       s={**rs, "streams": [{"media": 0, "participant": BOB}, {"media": 0, "participant": CAROL}]}, want={"refused": "bad-stream-map"})
    sv("stream-unknown-participant", "A stream's participant is not in the metadata.",
       s={**rs, "streams": [{"media": 0, "participant": "did:web:eve.example"}]}, want={"refused": "bad-stream-map"})
    sv("no-streams", "A recording session with no stream is refused.", s={**rs, "streams": []}, want={"refused": "bad-stream-map"})
    sv("media-not-integer", "A stream's media index must be an integer.", s={**rs, "streams": [{"media": "0", "participant": BOB}]},
       want={"refused": "bad-stream-map"})
    sv("direction-missing", "A named media section without a direction is not sendonly.", m=[{"type": "audio"}, media[1]],
       want={"refused": "direction"})
    sv("direction", "A recorded stream must be sendonly.", m=[{"type": "audio", "direction": "sendrecv"}, media[1]],
       want={"refused": "direction"})
    sv("unrecorded-section-any-direction", "A media section no stream names is not checked.",
       m=media + [{"type": "video", "direction": "inactive"}], want={"ok": True})
    sv("order-capability-before-session", "Several failures: the earliest check is reported.",
       r={**recorder, "capabilities": []}, s={**rs, "of": "01J9ZRECRD0000000000000002"}, want={"refused": "missing-capability"})
    return out


def vectors() -> list[dict]:
    return consent_vectors() + conversation_vectors() + session_vectors()
