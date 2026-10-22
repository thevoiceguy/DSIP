"""Presence Profile vectors (`presence/0.1`, v0.17 draft; spec-gaps 134–136), one function per vector kind.

Each kind's generator module calls its function here: the envelope pipeline's age rule for a `presence` record (§12.9,
P§3), its schema (P§5), its payload checks (P§3, P§5), the authority's handling (P§3, P§4, P§8) and the subscriber's
combining rule (P§4, P§5). Every expectation is written from the draft, not from an implementation.
"""
from __future__ import annotations

from .. import fixtures as F
from .common import NOW, base, signed, default_context, vector, accept, reject, uid

APH, BPH, BLA = F.did("alice-phone"), F.did("bob-phone"), F.did("bob-laptop")
ALICE, BOB = F.did("alice"), F.did("bob")
AUTH = "did:key:z6MkAuthorityRelay11111111111111111111111111"


def record(label, device=BPH, seq=1, state="busy", at=NOW, ttl=300, subject=F.BOB_WEB, frm=None, to=F.RELAY_WEB, **kw):
    """A §9.4 presence record as a device publishes it (P§3)."""
    fields = {"subject": subject, "state": state, "seq": seq, **kw}
    if device is not None:
        fields["device"] = device
    return base("presence", label, frm or device or BPH, at, ttl, to=to, **fields)


# ---------------------------------------------------------------- envelope: §12.9 age rule

def envelope_vectors() -> list[dict]:
    def ev(vid, desc, refs, env, expect):
        return vector(f"envelope/{vid}", "envelope", desc, refs, default_context(), {"envelope": env}, expect)

    ok = lambda state="busy": accept(type="presence", signer=BPH, identity=BPH, effective={"state": state})
    return [
        ev("presence-held-accepted", "A presence record signed 1,000 s ago with an hour's lifetime: its age is bounded by "
           "expires_at, not the 300 s replay window, because the authority keeps and forwards it (§12.9, P§3).",
           ["§12.9", "P§3"], signed(record("ph", at=NOW - 1000, ttl=3600), "bob-phone"), ok()),
        ev("presence-held-expired", "A presence record signed 4,000 s ago with an hour's lifetime is expired, not a "
           "replay-window rejection.", ["§12.9", "P§3"], signed(record("phx", at=NOW - 4000, ttl=3600), "bob-phone"),
           reject("expired")),
        ev("presence-future-rejected", "A presence record issued 400 s in the future: the future bound of the replay window "
           "still applies.", ["§12.9", "P§3"], signed(record("phf", at=NOW + 400), "bob-phone"), reject("replay-window")),
        ev("presence-validity-over-cap", "A presence record whose expires_at − issued_at is 3,601 s: over the 3,600 s cap.",
           ["§12.9", "P§8"], signed(record("phc", ttl=3601), "bob-phone"), reject("presence-validity")),
        ev("presence-validity-at-cap", "A presence record with exactly 3,600 s of lifetime is valid.", ["§12.9", "P§8"],
           signed(record("pha", ttl=3600), "bob-phone"), ok()),
        ev("presence-signer-mismatch", "A record signed by bob-phone naming bob-laptop as its device fails the payload "
           "check after the pipeline's own stages pass (P§3).", ["P§3", "§9.4"],
           signed(record("phm", device=BLA, frm=BPH), "bob-phone"), reject("presence-signer-mismatch", "presence.signer-mismatch")),
    ]


# ---------------------------------------------------------------- payload: the schema (P§5)

def payload_vectors() -> list[dict]:
    def pv(vid, desc, refs, payload, ok=True):
        return vector(f"payload/{vid}", "payload", desc, refs, {}, {"schema": "presence", "payload": payload},
                      accept() if ok else reject("schema-invalid"))

    r = record("pp")
    drop = lambda k: {key: v for key, v in r.items() if key != k}
    return [
        pv("presence-valid", "A device's presence record: subject, device, state, seq (§9.4, P§3).", ["§9.4", "P§3"], r),
        pv("presence-unknown-state-valid", "An unregistered state of the right shape is valid: the registry is open (P§5).",
           ["P§5"], {**r, "state": "in-transit"}),
        pv("presence-state-uppercase-invalid", "A state is a lower-case token (P§5).", ["P§5"], {**r, "state": "Busy"}, ok=False),
        pv("presence-state-too-long", "A state is at most 64 characters (P§5).", ["P§5"], {**r, "state": "a" * 65}, ok=False),
        pv("presence-state-at-length-cap", "A state of exactly 64 characters is valid (P§5).", ["P§5"], {**r, "state": "a" * 64}),
        pv("presence-missing-state", "A record names its state.", ["§9.4"], drop("state"), ok=False),
        pv("presence-missing-seq", "A record carries seq (§9.4, P§4).", ["§9.4", "P§4"], drop("seq"), ok=False),
        pv("presence-negative-seq", "seq is a non-negative integer.", ["§9.4"], {**r, "seq": -1}, ok=False),
        pv("presence-missing-subject", "A record names its subject.", ["§9.4"], drop("subject"), ok=False),
        pv("presence-missing-to", "A record is addressed to the authority (P§3).", ["P§3"], drop("to"), ok=False),
        pv("presence-without-device-valid", "A v0.16-form record without device is still a valid record (P§4).", ["P§4"],
           drop("device")),
        pv("presence-extra-field-invalid", "A record takes no field the profile does not define: note and activity are "
           "P§6's, not yet pinned.", ["§9.4", "P§6"], {**r, "note": "back at 3"}, ok=False),
        pv("presence-with-audience-and-endpoints-valid", "The §9.4 example's audience, profiles and endpoints are allowed.",
           ["§9.4"], {**r, "audience": "contacts-only", "profiles": ["interactive-media"],
                      "endpoints": [{"transport": "wss", "uri": "wss://relay.example.com/dsip/bob"}]}),
    ]


# ---------------------------------------------------------------- semantic: payload checks (P§3, P§5, P§9)

def semantic_vectors() -> list[dict]:
    def sv(vid, desc, refs, payload, expect):
        return vector(f"semantic/{vid}", "semantic", desc, refs, {"now": NOW, "supported": F.SUPPORTED}, {"payload": payload}, expect)

    r = record("ps")
    err = base("error", "perr", F.RELAY_WEB, NOW + 1, to=BPH, in_reply_to=r["id"], reason="presence.stale")
    out = [
        sv("presence-registered-state", "A registered state is its own effective state (P§5).", ["P§5"], r,
           accept(effective={"state": "busy"})),
        sv("presence-unknown-state-fallback", "An unknown state is accepted and shown as available, with a warning (P§5).",
           ["P§5"], {**r, "state": "in-transit"}, accept(effective={"state": "available"}, warnings=["presence-state-unknown"])),
        sv("presence-signer-mismatch", "A record's device must be its signer, from (P§3).", ["P§3", "§9.4"],
           {**r, "device": BLA}, reject("presence-signer-mismatch", "presence.signer-mismatch")),
        sv("presence-without-device-accepted", "A v0.16-form record without device passes the payload checks (P§4).", ["P§4"],
           {k: v for k, v in r.items() if k != "device"}, accept(effective={"state": "busy"})),
    ]
    for token in ("presence.signer-mismatch", "presence.lifetime", "presence.stale"):
        out.append(sv(f"reason-{token.replace('.', '-')}-registered", f"{token} is registered for error (P§9, v0.17, spec-gap 134).",
                      ["§15.4", "P§9"], {**err, "reason": token}, accept(effective={"reason": token, "fallback": "none"})))
    out.append(sv("reason-presence-unknown-condition", "presence is a reason category (P§9): an unregistered condition falls "
                  "back by category, not to session.failed.", ["§15.1", "§15.3", "P§9"], {**err, "reason": "presence.too-detailed"},
                  accept(effective={"reason": "presence.too-detailed", "fallback": "category"})))
    return out


# ---------------------------------------------------------------- state: the authority (P§3, P§4, P§8)

def state_vectors() -> list[dict]:
    from .state import IDENTITIES

    def step(event, emit, **snaps):
        return {"event": event, "expect": {"emit": emit, **snaps}}

    def trace(vid, desc, refs, steps, grace=None):
        ctx = {"component": "authority", "start": NOW, "identities": IDENTITIES}
        if grace is not None:
            ctx["presence_grace"] = grace
        return vector(f"state/{vid}", "state", desc, refs, ctx, {"steps": steps}, {})

    def rec(label, device=BPH, seq=1, state="busy", at=NOW, ttl=300, subject=BOB, frm=None):
        m = {"type": "presence", "id": uid(label, at), "from": frm or device or BPH, "to": AUTH, "subject": subject,
             "state": state, "seq": seq, "issued_at": at, "expires_at": at + ttl}
        if device is not None:
            m["device"] = device
        return m

    def body(asserted, *recs):
        b = {"event": "presence", "state": asserted}
        if recs:
            b["records"] = sorted(({"id": r["id"], "device": r["device"], "state": r["state"], "seq": r["seq"],
                                    "expires_at": r["expires_at"]} for r in recs), key=lambda x: x["device"])
        return b

    SUB = uid("psub", NOW)

    def notify(seq, b):
        return {"send": {"type": "notify", "to": APH, "subscription": SUB, "seq": seq, "state": "active", "body": b}}

    def error(r, reason, **extra):
        return {"send": {"type": "error", "to": r["from"], "in_reply_to": r["id"], "reason": reason, **extra}}

    def snap(*recs, grace=None):
        out: dict = {}
        for r in recs:
            s = {"seq": r["seq"], "state": r["state"], "expires_at": r["expires_at"]}
            if grace and r["device"] in grace:
                s["grace_until"] = grace[r["device"]]
            out.setdefault(r["subject"], {})[r["device"]] = s
        return out

    policy = step({"local": "policy", "target": BOB, "mode": "public"}, [])
    subscribe = step({"recv": {"type": "subscribe", "id": SUB, "from": APH, "to": AUTH, "target": BOB, "events": ["presence"],
                               "expires_in": 3600}}, [notify(1, body("offline"))])
    bind = lambda d=BPH, emit=None: step({"relay": "bind", "device": d, "identity": BOB}, emit if emit is not None else [])
    unbind = lambda d=BPH, emit=None: step({"relay": "unbind", "device": d, "identity": BOB}, emit if emit is not None else [])
    adv = lambda s, emit=None, **snaps: step({"advance": s}, emit or [], **snaps)
    out = []

    r1 = rec("p1")
    out.append(trace("presence-publish-accepted",
                     "A device's record is accepted without an answer and carried in every presence notify to its subject: "
                     "the device no longer counts in the authority's assertion, which says offline (P§3).", ["P§3", "§9.3", "§9.4"], [
        policy, subscribe,
        bind(emit=[notify(2, body("available"))]),
        step({"recv": r1}, [notify(3, body("offline", r1))], presence=snap(r1)),
    ]))

    r2 = rec("p2", seq=2, state="available", at=NOW + 10)
    out.append(trace("presence-replaces-by-seq", "A higher seq from the same device replaces its record (P§3).", ["P§3", "P§4"], [
        policy, subscribe, bind(emit=[notify(2, body("available"))]),
        step({"recv": r1}, [notify(3, body("offline", r1))]),
        adv(10),
        step({"recv": r2}, [notify(4, body("offline", r2))], presence=snap(r2)),
    ]))

    r5 = rec("p5", seq=5)
    same = rec("p5b", seq=5, state="away", at=NOW + 10)
    lower = rec("p4", seq=4, state="away", at=NOW + 10)
    out.append(trace("presence-stale-seq-refused",
                     "A record whose seq is not greater than the one held for its device is refused presence.stale and "
                     "changes nothing (P§3).", ["P§3", "P§9"], [
        policy, subscribe, bind(emit=[notify(2, body("available"))]),
        step({"recv": r5}, [notify(3, body("offline", r5))]),
        adv(10),
        step({"recv": same}, [error(same, "presence.stale")]),
        step({"recv": lower}, [error(lower, "presence.stale")], presence=snap(r5)),
    ]))

    no_device = rec("pnd", device=None)
    other_subject = rec("pos", subject=ALICE)
    other_device = rec("pod", device=BLA, frm=BPH)
    out.append(trace("presence-signer-mismatch",
                     "The authority refuses presence.signer-mismatch a record that names no device, one for a subject the "
                     "device is not bound for, and one naming another device (P§3).", ["P§3", "P§9"], [
        policy, bind(),
        step({"recv": no_device}, [error(no_device, "presence.signer-mismatch")]),
        step({"recv": other_subject}, [error(other_subject, "presence.signer-mismatch")]),
        step({"recv": other_device}, [error(other_device, "presence.signer-mismatch")], presence={}),
    ]))

    short = rec("psh", ttl=59)
    long_ = rec("plg", ttl=3601)
    edge = rec("ped", ttl=60)
    out.append(trace("presence-lifetime-refused",
                     "A record's lifetime must be 60–3,600 s: 59 and 3,601 are refused presence.lifetime, 60 is accepted "
                     "(P§8).", ["P§3", "P§8", "P§9"], [
        policy, bind(),
        step({"recv": short}, [error(short, "presence.lifetime")]),
        step({"recv": long_}, [error(long_, "presence.lifetime")]),
        step({"recv": edge}, [], presence=snap(edge)),
    ]))

    q1 = rec("pq1")
    q2 = rec("pq2", seq=2, state="away", at=NOW + 3)
    q3 = rec("pq3", seq=3, state="away", at=NOW + 5)
    out.append(trace("presence-rate-limited",
                     "A device's next record within 5 s of its last accepted one is refused policy.rate-limited with the "
                     "seconds left; at 5 s it is accepted (P§8).", ["P§3", "P§8"], [
        policy, subscribe, bind(emit=[notify(2, body("available"))]),
        step({"recv": q1}, [notify(3, body("offline", q1))]),
        adv(3),
        step({"recv": q2}, [error(q2, "policy.rate-limited", retry_after=2)]),
        adv(2),
        step({"recv": q3}, [notify(4, body("offline", q3))], presence=snap(q3)),
    ]))

    phone = rec("ppd", seq=5)
    laptop = rec("pld", device=BLA, seq=3, state="away")
    out.append(trace("presence-seq-per-device",
                     "seq is ordered per (subject, device): the laptop's seq 3 after the phone's seq 5 is not stale, and "
                     "the publish interval is per device. While the laptop holds no record it keeps the assertion "
                     "available; the body carries both records, by device (P§4).", ["P§4", "P§3"], [
        policy, subscribe, bind(emit=[notify(2, body("available"))]),
        bind(BLA),
        step({"recv": phone}, [notify(3, body("available", phone))]),
        step({"recv": laptop}, [notify(4, body("offline", phone, laptop))], presence=snap(phone, laptop)),
    ]))

    e1 = rec("pe1", ttl=60)
    e2 = rec("pe2", seq=1, state="away", at=NOW + 60)
    out.append(trace("presence-expiry-falls-back-to-assertion",
                     "At its expires_at the record is dropped and the bound device counts in the assertion again; its seq is "
                     "forgotten, so seq 1 is accepted afresh (P§3).", ["P§3", "§9.3"], [
        policy, subscribe, bind(emit=[notify(2, body("available"))]),
        step({"recv": e1}, [notify(3, body("offline", e1))]),
        adv(59),
        adv(1, [notify(4, body("available"))], presence={}),
        step({"recv": e2}, [notify(5, body("offline", e2))]),
    ]))

    g1 = rec("pg1")
    out.append(trace("presence-unbind-grace",
                     "A device that unbinds keeps its record for T-Presence-Grace (60 s): no notify at the unbind, since the "
                     "body is unchanged, and the record is dropped when the grace runs out (P§3, P§8).", ["P§3", "P§8"], [
        policy, subscribe, bind(emit=[notify(2, body("available"))]),
        step({"recv": g1}, [notify(3, body("offline", g1))]),
        adv(10),
        unbind(),
        adv(59, presence=snap(g1, grace={BPH: NOW + 70})),
        adv(1, [notify(4, body("offline"))], presence={}),
    ]))

    out.append(trace("presence-rebind-within-grace",
                     "A device that binds again within the grace keeps its record as if it had never left: nothing is sent, "
                     "and the record lives to its own expires_at (P§3).", ["P§3", "P§8"], [
        policy, subscribe, bind(emit=[notify(2, body("available"))]),
        step({"recv": g1}, [notify(3, body("offline", g1))]),
        adv(10),
        unbind(),
        adv(30),
        bind(),
        adv(60, presence=snap(g1)),
        adv(200, [notify(4, body("available"))], presence={}),
    ]))

    out.append(trace("presence-second-unbind-keeps-the-grace",
                     "The grace runs from the first unbind: a second unbind while it runs changes nothing, so the record "
                     "is still dropped 60 s after the first (P§3).", ["P§3", "P§8"], [
        policy, subscribe, bind(emit=[notify(2, body("available"))]),
        step({"recv": g1}, [notify(3, body("offline", g1))]),
        adv(10),
        unbind(),
        adv(20),
        unbind(),
        adv(39, presence=snap(g1, grace={BPH: NOW + 70})),
        adv(1, [notify(4, body("offline"))], presence={}),
    ]))

    z1 = rec("pz1")
    z2 = rec("pz2", seq=2, state="away", at=NOW + 2)
    out.append(trace("presence-rate-limit-runs-after-a-drop",
                     "The publish interval runs from the last accepted record even when that record was dropped: with a "
                     "grace of 0 the unbind drops it, and a record 2 s after it is refused with 3 s left (P§3, P§8).",
                     ["P§3", "P§8"], [
        policy, subscribe, bind(emit=[notify(2, body("available"))]),
        step({"recv": z1}, [notify(3, body("offline", z1))]),
        step({"relay": "unbind", "device": BPH, "identity": BOB}, [notify(4, body("offline"))], presence={}),
        bind(emit=[notify(5, body("available"))]),
        adv(2),
        step({"recv": z2}, [error(z2, "policy.rate-limited", retry_after=3)], presence={}),
    ], grace=0))

    out.append(trace("presence-grace-zero",
                     "With a grace of 0 the authority drops the record at the unbind (P§8 bounds 0–300 s).", ["P§3", "P§8"], [
        policy, subscribe, bind(emit=[notify(2, body("available"))]),
        step({"recv": g1}, [notify(3, body("offline", g1))]),
        step({"relay": "unbind", "device": BPH, "identity": BOB}, [notify(4, body("offline"))], presence={}),
    ], grace=0))

    out.append(trace("presence-binding-change-without-body-change",
                     "A binding change notifies only when it changes the body: a second device binding, and one of two "
                     "unbinding, leave the assertion available (P§3).", ["P§3", "§9.3"], [
        policy, subscribe,
        bind(emit=[notify(2, body("available"))]),
        bind(BLA),
        unbind(),
        unbind(BLA, [notify(3, body("offline"))]),
    ]))

    x1 = rec("px1", ttl=120)
    x2 = rec("px2", device=BLA, state="away", ttl=120)
    out.append(trace("presence-expiry-several-one-notify",
                     "Two records expiring at once give each subscription one notify for the subject (P§3).", ["P§3"], [
        policy, subscribe, bind(emit=[notify(2, body("available"))]), bind(BLA),
        step({"recv": x1}, [notify(3, body("available", x1))]),
        step({"recv": x2}, [notify(4, body("offline", x1, x2))]),
        adv(120, [notify(5, body("available"))], presence={}),
    ]))
    return out


# ---------------------------------------------------------------- presence: the combining rule (P§4, P§5)

def presence_vectors() -> list[dict]:
    def agg(vid, desc, refs, records, expect, asserted=None):
        inp = {"check": "aggregate", "records": records}
        if asserted is not None:
            inp["asserted"] = asserted
        return vector(f"presence/{vid}", "presence", desc, refs, {"now": NOW}, inp, expect)

    def r(state, device=BPH, expires_at=NOW + 100):
        out = {"state": state, "expires_at": expires_at}
        if device is not None:
            out["device"] = device
        return out

    win = lambda state, token=None, source="record": {"state": state, "token": token or state, "source": source}
    P4, P5 = ["P§4"], ["P§4", "P§5"]
    return [
        agg("aggregate-busy-beats-available", "busy ranks above available.", P4, [r("available"), r("busy", BLA)], win("busy")),
        agg("aggregate-dnd-wins", "dnd ranks above every other state.", P4, [r("busy"), r("dnd", BLA), r("available", APH)],
            win("dnd")),
        agg("aggregate-available-beats-away", "available ranks above away.", P4, [r("away"), r("available", BLA)], win("available")),
        agg("aggregate-all-offline", "Every device offline: offline, from the records.", P4, [r("offline"), r("offline", BLA)],
            win("offline"), asserted="offline"),
        agg("aggregate-no-records", "No record and an offline assertion: offline, from nothing.", P4, [], win("offline", source="none"),
            asserted="offline"),
        agg("aggregate-expired-ignored", "A record whose expires_at is now is no longer valid; the away record stands.", P4,
            [r("busy", expires_at=NOW), r("away", BLA)], win("away")),
        agg("aggregate-only-expired", "With only expired records the identity is offline.", P4, [r("busy", expires_at=NOW - 1)],
            win("offline", source="none")),
        agg("aggregate-unknown-state-fallback", "An unknown state ranks and shows as available, its token kept (P§5).", P5,
            [r("away"), r("in-transit", BLA)], win("available", "in-transit")),
        agg("aggregate-unknown-below-busy", "An unknown state ranks as available, so below busy.", P5,
            [r("busy"), r("in-transit", BLA)], win("busy")),
        agg("aggregate-registered-beats-unknown-tie", "Of equal rank, the registered available comes before an unknown state.",
            P5, [r("in-transit"), r("available", BLA)], win("available")),
        agg("aggregate-unknown-code-point-order", "Among unknown states of equal rank, the lower in code-point order wins.", P5,
            [r("zz-later"), r("in-transit", BLA)], win("available", "in-transit")),
        agg("aggregate-assertion-counts", "An available assertion is a candidate: a bound device without a record outranks "
            "an away record. Rendered as the authority's claim (§9.3).", P4, [r("away")], win("available", source="assertion"),
            asserted="available"),
        agg("aggregate-record-before-assertion", "A record and the assertion both available: the record comes first.", P4,
            [r("available")], win("available"), asserted="available"),
        agg("aggregate-unknown-record-before-assertion", "An unknown-state record and an available assertion rank the same: "
            "the record comes first, so the device's own token is shown, not the authority's claim.", P5,
            [r("in-transit")], win("available", "in-transit"), asserted="available"),
        agg("aggregate-assertion-below-busy", "A busy record outranks an available assertion.", P4, [r("busy")], win("busy"),
            asserted="available"),
        agg("aggregate-assertion-only", "No record, an available assertion: available, from the assertion.", P4, [],
            win("available", source="assertion"), asserted="available"),
        agg("aggregate-offline-record-and-assertion", "One device's record says offline while another bound device has none: "
            "available, from the assertion.", P4, [r("offline")], win("available", source="assertion"), asserted="available"),
        agg("aggregate-legacy-record-no-device", "A v0.16-form record without device counts as one unnamed device's.", P4,
            [r("busy", device=None), r("away")], win("busy")),
    ]
