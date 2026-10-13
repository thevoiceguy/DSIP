"""`recording/` vectors — Recording Profile draft (C§4–C§6; spec-gap 107). Expectations are written out by hand."""
from __future__ import annotations

import hashlib

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


def add_devices_vectors() -> list[dict]:
    out = []
    R = ["C§5", "M§7.2"]
    ALICE_PHONE = {"device": "did:key:z6MkAlicePhone", "identity": "did:web:alice.example", "capabilities": ["dsip.signaling", "dsip.messaging"]}
    BOB_PHONE = {"device": "did:key:z6MkBobPhone", "identity": BOB, "capabilities": ["dsip.signaling", "dsip.messaging"]}
    BOB_LAPTOP = {"device": "did:key:z6MkBobLaptop", "identity": BOB, "capabilities": ["dsip.signaling", "dsip.messaging"]}
    BOB_REC = {"device": "did:key:z6MkBobRec", "identity": BOB, "capabilities": ["dsip.signaling", "dsip.messaging", "dsip.record"]}

    def av(vid, desc, inp, want, refs=R):
        out.append(rv(f"add-devices-{vid}", desc, refs, {"check": "add-devices", **inp}, want))
    def conv(kps, self_device="did:key:z6MkAlicePhone", target=BOB, purpose="conversation"):
        me = BOB if "Bob" in self_device else "did:web:alice.example"
        return {"target": target, "self_identity": me, "self_device": self_device, "purpose": purpose, "key_packages": kps}
    av("all-devices-with-recorder", "Every device of the identity is added, the recorder included, so a new conversation is recorded too.",
       conv([BOB_PHONE, BOB_REC, BOB_LAPTOP]), {"add": ["did:key:z6MkBobPhone", "did:key:z6MkBobRec", "did:key:z6MkBobLaptop"]})
    av("recorder-only", "Only the recorder has KeyPackages: the identity is not added — a recorder never stands in for the person.",
       conv([BOB_REC]), {"refused": "recorder-only"})
    av("own-other-devices", "The creator adds its own other devices, the recorder included, never itself.",
       conv([BOB_PHONE, BOB_LAPTOP, BOB_REC], self_device="did:key:z6MkBobPhone"), {"add": ["did:key:z6MkBobLaptop", "did:key:z6MkBobRec"]})
    av("own-only-recorder-left", "Besides itself the creator's identity has only its recorder: it is added — the person is "
       "present through the creating device.", conv([BOB_PHONE, BOB_REC], self_device="did:key:z6MkBobPhone"),
       {"add": ["did:key:z6MkBobRec"]})
    av("personal-never-recorder", "The personal group never takes a recorder device.",
       conv([BOB_PHONE, BOB_REC, BOB_LAPTOP], self_device="did:key:z6MkBobPhone", purpose="personal"), {"add": ["did:key:z6MkBobLaptop"]})
    av("personal-only-recorder", "For the personal group a lone recorder leaves nothing to add.",
       conv([BOB_PHONE, BOB_REC], self_device="did:key:z6MkBobPhone", purpose="personal"), {"refused": "no-key-packages"})
    av("none", "No KeyPackage at all.", conv([]), {"refused": "no-key-packages"})
    av("other-identity-ignored", "Entries for another identity are not candidates.", conv([ALICE_PHONE, BOB_PHONE]),
       {"add": ["did:key:z6MkBobPhone"]})
    av("duplicate-device-once", "A device with two KeyPackages (one-time and last resort) is added once.",
       conv([BOB_PHONE, BOB_PHONE, BOB_LAPTOP]), {"add": ["did:key:z6MkBobPhone", "did:key:z6MkBobLaptop"]})
    # C§9 (v0.13, spec-gap 123): a record-keeper's devices all carry dsip.record, so the party cannot add it; the
    # record-keeper opens the conversation instead, its recorder device adding the party's devices.
    KEEPER = {"device": "did:key:z6MkKeeper", "identity": REC, "capabilities": ["dsip.messaging", "dsip.record"]}
    av("party-cannot-add-record-keeper", "A party adding its record-keeper finds only recorder devices: refused, so the "
       "record-keeper opens the conversation (C§9).", {"target": REC, "self_identity": "did:web:alice.example",
       "self_device": "did:key:z6MkAlicePhone", "purpose": "conversation", "key_packages": [KEEPER]}, {"refused": "recorder-only"},
       ["C§5", "C§9", "M§7.2"])
    av("record-keeper-opens", "The record-keeper's recorder device opens the conversation with a party: every device of "
       "the party is added (C§9).", {"target": BOB, "self_identity": REC, "self_device": "did:key:z6MkKeeper",
       "purpose": "conversation", "key_packages": [BOB_PHONE, BOB_LAPTOP, KEEPER]},
       {"add": ["did:key:z6MkBobPhone", "did:key:z6MkBobLaptop"]}, ["C§5", "C§9", "M§7.2"])
    return out


def call_record_vectors() -> list[dict]:
    """C§9 (v0.13, spec-gap 121): a leg's outcome, and matching a record's evidence against kept frames."""
    out = []

    def oc(vid, desc, direction, answered, ended_by, reason, want):
        out.append(rv(f"call-record-outcome-{vid}", desc, ["C§9"], {"check": "call-record-outcome", "direction": direction,
                   "answered": answered, "ended_by": ended_by, "reason": reason}, {"outcome": want}))

    oc("outbound-answered", "An answered outbound leg.", "outbound", True, "remote", "user.hangup", "answered")
    oc("inbound-answered", "An inbound leg answered on this device.", "inbound", True, "local", "user.hangup", "answered")
    oc("answered-then-transport", "Answered first: a call that later lost its connection was still answered.",
       "outbound", True, "transport", "transport.no-response", "answered")
    oc("answered-elsewhere", "An inbound leg cancelled because another device answered (§12.7).", "inbound", False,
       "remote", "session.answered-elsewhere", "answered-elsewhere")
    oc("ended-by-transport", "A leg that ended with no message failed.", "inbound", False, "transport",
       "transport.no-response", "failed")
    oc("transport-category", "A transport-category reason fails the leg, whoever sent it.", "outbound", False, "remote",
       "transport.no-response", "failed")
    oc("unknown-transport-condition", "An unregistered transport condition still has the transport category (§15).",
       "outbound", False, "remote", "transport.carrier-pigeon-lost", "failed")
    oc("inbound-declined-here", "The user declined on this device.", "inbound", False, "local", "user.declined", "declined")
    oc("inbound-declined-on-sibling", "Declined on another of the party's devices: this leg was missed.", "inbound", False,
       "remote", "user.declined", "missed")
    oc("outbound-declined-by-callee", "The callee declined.", "outbound", False, "remote", "user.declined", "declined")
    oc("outbound-local-declined-is-cancelled", "A caller ending its own call is cancelling, whatever token it used.",
       "outbound", False, "local", "user.declined", "cancelled")
    oc("inbound-caller-cancelled", "The caller gave up: missed.", "inbound", False, "remote", "session.cancelled", "missed")
    oc("inbound-ring-timeout", "Nobody answered before the ring timer: missed.", "inbound", False, "local",
       "session.timeout", "missed")
    oc("inbound-busy", "A leg this device refused as busy was still a call the party missed.", "inbound", False, "local",
       "endpoint.busy", "missed")
    oc("outbound-cancelled", "The caller hung up before an answer.", "outbound", False, "local", "session.cancelled",
       "cancelled")
    oc("outbound-busy", "The callee was busy.", "outbound", False, "remote", "endpoint.busy", "rejected")
    oc("outbound-unknown-reason", "An unregistered reason from the callee: rejected.", "outbound", False, "remote",
       "policy.something-new", "rejected")

    f1 = '{"protected":"eyJhbGciOiJFZERTQSJ9","payload":"eyJ0eXBlIjoiaW52aXRlIn0","signature":"c2ln"}'
    f2 = '{"protected":"eyJhbGciOiJFZERTQSJ9","payload":"eyJ0eXBlIjoiYW5zd2VyIn0","signature":"c2ln"}'
    f1_spaced = '{"protected": "eyJhbGciOiJFZERTQSJ9", "payload": "eyJ0eXBlIjoiaW52aXRlIn0", "signature": "c2ln"}'
    h = lambda f: hashlib.sha256(f.encode()).hexdigest()  # noqa: E731 — SHA-256 of the bytes, the rule itself
    other = "f" * 64

    def ev(vid, desc, evidence, frames, matched, unmatched):
        out.append(rv(f"call-record-evidence-{vid}", desc, ["C§9", "§10.2"], {"check": "call-record-evidence",
                   "evidence": evidence, "frames": frames}, {"matched": matched, "unmatched": unmatched}))

    ev("all-matched", "Each entry matches a kept frame by the SHA-256 of its bytes.", [h(f1), h(f2)], [f2, f1],
       [h(f1), h(f2)], [])
    ev("one-missing", "An entry no kept frame hashes to is unmatched; input order is kept.", [h(f1), other, h(f2)], [f1, f2],
       [h(f1), h(f2)], [other])
    ev("reserialised-frame-does-not-match", "A frame that differs only in whitespace is different bytes: re-serialising "
       "loses the match (§10.2).", [h(f1)], [f1_spaced], [], [h(f1)])
    ev("spaced-frame-matches-its-own-bytes", "The digest is of the bytes as kept, whatever their spacing.", [h(f1_spaced)],
       [f1, f1_spaced], [h(f1_spaced)], [])
    ev("repeated-entry", "A repeated entry is listed each time.", [h(f1), h(f1)], [f1], [h(f1), h(f1)], [])
    ev("no-frames", "With nothing kept, nothing matches.", [h(f1)], [], [], [h(f1)])
    ev("no-evidence", "A record without evidence matches nothing.", [], [f1], [], [])
    return out


def vectors() -> list[dict]:
    return consent_vectors() + conversation_vectors() + session_vectors() + add_devices_vectors() + call_record_vectors()
