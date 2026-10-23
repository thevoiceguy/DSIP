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
        ev("presence-at-expiry", "A presence record received at exactly its expires_at is expired (§12.9: valid while "
           "now < expires_at; spec-gap 141), as the authority drops it then (P§3).", ["§12.9", "P§3"],
           signed(record("phe", at=NOW - 300), "bob-phone"), reject("expired")),
        vector("envelope/presence-id-already-seen", "envelope", "A presence record whose id the receiver has already seen is "
               "accepted: a record is forwarded in notify bodies for its lifetime, so its seq, not its id, decides a "
               "re-observed record (§12.9, P§3, spec-gap 141).", ["§12.9", "P§3"],
               default_context(seen_ids=[record("phs")["id"]]), {"envelope": signed(record("phs"), "bob-phone")}, ok()),
        ev("presence-future-rejected", "A presence record issued 400 s in the future: the future bound of the replay window "
           "still applies.", ["§12.9", "P§3"], signed(record("phf", at=NOW + 400), "bob-phone"), reject("replay-window")),
        ev("presence-validity-over-cap", "A presence record whose expires_at − issued_at is 3,601 s: over the 3,600 s cap.",
           ["§12.9", "P§8"], signed(record("phc", ttl=3601), "bob-phone"), reject("presence-validity")),
        ev("presence-validity-at-cap", "A presence record with exactly 3,600 s of lifetime is valid.", ["§12.9", "P§8"],
           signed(record("pha", ttl=3600), "bob-phone"), ok()),
        ev("grant-revocation-accepted", "A grant-revocation signed by the granting identity's device passes the pipeline "
           "as any core message (§19.4, P§7).", ["§19.4", "P§7"],
           signed(base("grant-revocation", "erv", BPH, NOW, to=F.RELAY_WEB, grant=uid("erv-g", NOW - 600), grantee=ALICE,
                       valid_until=NOW + 86400), "bob-phone"), accept(type="grant-revocation", signer=BPH, identity=BPH)),
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
        pv("presence-audience-uppercase-invalid", "An audience is a lower-case token (P§6, spec-gap 145).", ["P§6"],
           {**r, "audience": "Family"}, ok=False),
        pv("presence-audience-too-long", "An audience is at most 64 characters (P§6).", ["P§6"], {**r, "audience": "a" * 65},
           ok=False),
    ] + grant_payload_vectors()


def grant_payload_vectors() -> list[dict]:
    """§19.4 (v0.17): a grant's presence_audience (spec-gap 145), the grant-revocation message (spec-gap 147) and a
    subscribe presenting a grant in claims (spec-gap 144)."""
    def pv(vid, desc, refs, schema, payload, ok=True):
        return vector(f"payload/{vid}", "payload", desc, refs, {}, {"schema": schema, "payload": payload},
                      accept() if ok else reject("schema-invalid"))

    g = base("grant", "pg", F.did("bob-phone"), NOW, to=ALICE, session=uid("pg-intro", NOW - 60),
             scope=["dsip.invite", "dsip.subscribe"], valid_until=NOW + 86400)
    rv = base("grant-revocation", "prv", F.did("bob-phone"), NOW, to=F.RELAY_WEB, grant=g["id"], grantee=ALICE,
              valid_until=NOW + 86400)
    sub = base("subscribe", "psg", APH, NOW, to=F.RELAY_WEB, target=BOB, events=["presence"], expires_in=3600,
               claims=[{"type": "dsip-grant", "grant": {"protected": "e30", "payload": "e30", "signature": "AA"}}])
    drop = lambda m, k: {key: v for key, v in m.items() if key != k}
    return [
        pv("grant-presence-audience-valid", "A grant may name the presence audience its subscriber sees (§19.4, P§6).",
           ["§19.4", "P§6"], "grant", {**g, "presence_audience": "family"}),
        pv("grant-presence-audience-uppercase-invalid", "presence_audience is a lower-case token (§19.4, P§6).",
           ["§19.4", "P§6"], "grant", {**g, "presence_audience": "Family"}, ok=False),
        pv("grant-revocation-valid", "A grant-revocation names the grant, its grantee and its valid_until (§19.4, P§7).",
           ["§19.4", "P§7"], "grant-revocation", rv),
        pv("grant-revocation-missing-grant", "A revocation names the grant it withdraws.", ["§19.4"], "grant-revocation",
           drop(rv, "grant"), ok=False),
        pv("grant-revocation-missing-valid-until", "A revocation carries the grant's valid_until, how long it is kept "
           "(§19.4).", ["§19.4"], "grant-revocation", drop(rv, "valid_until"), ok=False),
        pv("grant-revocation-is-not-session-scoped", "A revocation carries no session (§19.4).", ["§19.4"],
           "grant-revocation", {**rv, "session": uid("prv-s", NOW)}, ok=False),
        pv("subscribe-with-grant-claim-valid", "A subscribe may present a grant in claims as {type: dsip-grant, grant} "
           "(§9.3, P§6).", ["§9.3", "P§6"], "subscribe", sub),
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
    return out + admission_vectors()


# ---------------------------------------------------------------- state: who may watch, audiences, shares (P§6, P§7)

def admission_vectors() -> list[dict]:
    """P§6 (spec-gaps 144–146) and P§7 (spec-gap 147): admission without a policy, by a presented grant, audiences, a
    body per subscription, and a grant's expiry and revocation ending what it admitted."""
    from .state import IDENTITIES

    CPH, CAROL, MAL = F.did("carol-phone"), F.did("carol"), F.did("mallory")  # mallory: a did:key identity on its own

    def step(event, emit, **snaps):
        return {"event": event, "expect": {"emit": emit, **snaps}}

    def trace(vid, desc, refs, steps):
        ctx = {"component": "authority", "start": NOW, "identities": IDENTITIES}
        return vector(f"state/{vid}", "state", desc, refs, ctx, {"steps": steps}, {})

    def rec(label, device=BPH, seq=1, state="busy", at=NOW, ttl=300, audience=None):
        m = {"type": "presence", "id": uid(label, at), "from": device, "to": AUTH, "subject": BOB, "device": device,
             "state": state, "seq": seq, "issued_at": at, "expires_at": at + ttl}
        if audience is not None:
            m["audience"] = audience
        return m

    def summary(r):
        out = {"id": r["id"], "device": r["device"], "state": r["state"], "seq": r["seq"], "expires_at": r["expires_at"]}
        if "audience" in r:
            out["audience"] = r["audience"]
        return out

    def body(asserted, *recs):
        b = {"event": "presence", "state": asserted}
        if recs:
            b["records"] = [summary(r) for r in sorted(recs, key=lambda r: (r["device"], r.get("audience", "")))]
        return b

    def grant(label, to=ALICE, issuer=BOB, scope=("dsip.subscribe",), until=NOW + 86400, audience=None, verified=None):
        """A presented grant as the host summarises it after verifying the envelope: `identity` is the identity its
        signer acts for (§7.4); `verified: false` when its signature or delegation did not verify."""
        g = {"id": uid(label, NOW - 1000), "from": BPH, "identity": issuer, "to": to, "scope": list(scope), "valid_until": until}
        if audience is not None:
            g["presence_audience"] = audience
        if verified is not None:
            g["verified"] = verified
        return g

    def subscribe(label, frm=APH, grants=(), at=NOW, target=BOB, expires_in=3600):
        m = {"type": "subscribe", "id": uid(label, at), "from": frm, "to": AUTH, "target": target, "events": ["presence"],
             "expires_in": expires_in}
        if grants:
            m["claims"] = [{"type": "dsip-grant", "grant": g} for g in grants]
        return m

    def notify(sub, seq, b, state="active", reason=None):
        n = {"type": "notify", "to": sub["from"], "subscription": sub["id"], "seq": seq, "state": state}
        if reason:
            n["reason"] = reason
        n["body"] = b
        return {"send": n}

    def in_order(*emits):
        """notifies to several subscriptions of one subject go in subscription order (P§3)"""
        return sorted(emits, key=lambda e: e["send"]["subscription"])

    def blocked(sub):
        return {"send": {"type": "reject", "to": sub["from"], "session": sub["id"], "reason": "policy.blocked"}}

    def subsnap(sub, seq, subscriber, expires_at=NOW + 3600, **extra):
        return {sub["id"]: {"subscriber": subscriber, "target": BOB, "events": ["presence"], "seq": seq,
                            "expires_at": expires_at, **extra}}

    def revocation(label, g, frm=BPH, at=NOW):
        return {"type": "grant-revocation", "id": uid(label, at), "from": frm, "to": AUTH, "grant": g["id"],
                "grantee": g["to"], "valid_until": g["valid_until"]}

    bind = lambda d=BPH: step({"relay": "bind", "device": d, "identity": BOB}, [])
    adv = lambda s, emit=None, **snaps: step({"advance": s}, emit or [], **snaps)
    out = []

    stranger = subscribe("a-stranger")
    own = subscribe("a-own", frm=BLA)
    r1 = rec("a-r1")
    out.append(trace("presence-private-by-default",
                     "With no policy for Bob, a subscriber that presents nothing gets the uniform policy.blocked, while "
                     "Bob's own laptop is admitted and sees his phone's record (§9.2, §9.3, P§6, spec-gap 144).",
                     ["§9.2", "§9.3", "P§6"], [
        bind(),
        step({"recv": stranger}, [blocked(stranger)]),
        step({"recv": own}, [notify(own, 1, body("available"))]),
        step({"recv": r1}, [notify(own, 2, body("offline", r1))], subscriptions=subsnap(own, 2, BOB, own=True)),
    ]))

    g = grant("a-g1")
    by_grant = subscribe("a-bygrant", grants=[g])
    out.append(trace("presence-grant-admits",
                     "With no policy, Alice is admitted by the grant she presents: issued by Bob's identity, to hers, "
                     "scope dsip.subscribe, valid_until after now. The authority had never seen the grant (P§6, "
                     "spec-gap 144).", ["P§6", "§19.4", "§9.3"], [
        bind(),
        step({"recv": by_grant}, [notify(by_grant, 1, body("available"))],
             subscriptions=subsnap(by_grant, 1, ALICE, grant=g["id"])),
        step({"recv": r1}, [notify(by_grant, 2, body("offline", r1))]),
    ]))

    bad = [
        ("unverified", grant("a-bad1", verified=False)),
        ("issued by another identity", grant("a-bad2", issuer=CAROL)),
        ("to another identity", grant("a-bad3", to=CAROL)),
        ("without dsip.subscribe", grant("a-bad4", scope=("dsip.invite", "dsip.message"))),
        ("ending now", grant("a-bad5", until=NOW)),
    ]
    steps = [bind()]
    for i, (_, bg) in enumerate(bad):
        sb = subscribe(f"a-badsub{i}", grants=[bg])
        steps.append(step({"recv": sb}, [blocked(sb)]))
    steps[-1]["expect"]["subscriptions"] = {}
    out.append(trace("presence-grant-not-admitting",
                     "A presented grant admits only when it verifies, was issued by the target's identity, is to the "
                     "subscriber's identity, has dsip.subscribe in its scope and its valid_until is after now (exclusive, "
                     "§12.9). Each of these fails alone and gets policy.blocked: " + "; ".join(w for w, _ in bad) + " (P§6).",
                     ["P§6", "§12.9", "§19.4"], steps))

    fam = grant("a-fam", audience="family")
    first = subscribe("a-first", grants=[grant("a-bad6", scope=("dsip.invite",)), fam, grant("a-work", audience="work")])
    out.append(trace("presence-first-admitting-grant",
                     "Of several presented grants the first that admits, in claims order, is used: the first names only "
                     "dsip.invite, so the family grant admits and fixes the subscription's audience (P§6, spec-gap 145).",
                     ["P§6"], [
        bind(),
        step({"recv": first}, [notify(first, 1, body("available"))],
             subscriptions=subsnap(first, 1, ALICE, grant=fam["id"], audience="family")),
    ]))

    carol = subscribe("a-carol", frm=CPH)
    out.append(trace("presence-policy-admits-with-its-audience",
                     "An authority's own policy still admits: Carol is in the allow list, which names the audience work, "
                     "so she sees Bob's work record and his records with no audience, but not his family record (P§6).",
                     ["P§6", "§9.3"], [
        bind(),
        step({"local": "policy", "target": BOB, "mode": "allow", "allow": [CAROL], "audience": "work"}, []),
        step({"recv": carol}, [notify(carol, 1, body("available"))], subscriptions=subsnap(carol, 1, CAROL, audience="work")),
        step({"recv": (fr := rec("a-pf", audience="family"))}, []),
        step({"recv": (wr := rec("a-pw", state="away", audience="work"))}, [notify(carol, 2, body("offline", wr))]),
    ]))

    # spec-gap 149 (a): a capability the authority issued for a target makes it seen, before it ever binds
    cap = lambda sub, token: {**sub, "capability": token}
    pre = subscribe("a-cap-pre", target=MAL)
    plain = subscribe("a-cap-plain", target=MAL)
    wrong = cap(subscribe("a-cap-wrong", target=MAL), "follow-wrong")
    held = cap(subscribe("a-cap-held", target=MAL), "follow-mal")
    out.append(trace("presence-capability-makes-target-seen",
                     "Mallory has never bound here and has no policy. Before a capability is issued for her, Alice is "
                     "refused; once it is, the capability admits Alice although Mallory has still never bound, and her "
                     "body asserts offline. Presenting nothing, or another token, is still the uniform policy.blocked "
                     "(§9.3, P§6 rule 3, spec-gap 149).", ["§9.3", "P§6"], [
        step({"recv": pre}, [blocked(pre)]),
        step({"local": "issue_capability", "token": "follow-mal", "target": MAL}, []),
        step({"recv": plain}, [blocked(plain)]),
        step({"recv": wrong}, [blocked(wrong)]),
        step({"recv": held}, [notify(held, 1, {"event": "presence", "state": "offline"})],
             subscriptions={held["id"]: {"subscriber": ALICE, "target": MAL, "events": ["presence"], "seq": 1,
                                         "expires_at": NOW + 3600}}),
    ]))

    fam_sub = subscribe("a-famsub", grants=[fam])
    work_sub = subscribe("a-worksub", frm=CPH, grants=[grant("a-cwork", to=CAROL, audience="work")])
    plain_sub = subscribe("a-plainsub", frm=MAL, grants=[grant("a-plain", to=MAL)])
    own_sub = subscribe("a-ownsub", frm=BLA)
    subs = sorted([fam_sub, work_sub, plain_sub, own_sub], key=lambda x: x["id"])
    base_rec = rec("a-base", state="available")
    fam_rec = rec("a-famrec", state="busy", audience="family")
    work_rec = rec("a-workrec", state="away", audience="work")
    seen = {fam_sub["id"]: [base_rec, fam_rec], work_sub["id"]: [base_rec, work_rec], plain_sub["id"]: [base_rec],
            own_sub["id"]: [base_rec, fam_rec, work_rec]}
    def after(recs_now, prev_count):
        """notifies for every subscription whose visible records changed, in subscription order"""
        emits = []
        for sb in subs:
            vis = [r for r in seen[sb["id"]] if r in recs_now]
            if len(vis) != prev_count[sb["id"]]:
                prev_count[sb["id"]] = len(vis)
                seqs[sb["id"]] += 1
                emits.append(notify(sb, seqs[sb["id"]], body("offline" if vis else "available", *vis)))
        return emits
    seqs = {sb["id"]: 1 for sb in subs}
    counts = {sb["id"]: 0 for sb in subs}
    steps = [bind()] + [step({"recv": sb}, [notify(sb, 1, body("available"))]) for sb in
                        [fam_sub, work_sub, plain_sub, own_sub]]
    have = []
    for r in (base_rec, fam_rec, work_rec):
        have.append(r)
        steps.append(step({"recv": r}, after(have, counts)))
    steps[-1]["expect"]["presence"] = {BOB: {BPH: {"seq": 1, "state": "available", "expires_at": NOW + 300},
                                             f"{BPH}/family": {"seq": 1, "state": "busy", "expires_at": NOW + 300},
                                             f"{BPH}/work": {"seq": 1, "state": "away", "expires_at": NOW + 300}}}
    out.append(trace("presence-audiences",
                     "Bob's phone publishes a record with no audience, one for family and one for work, in the same "
                     "second: per (device, audience) they are neither stale nor rate-limited. A family grant sees the "
                     "first two, a work grant the first and the work record, a grant naming no audience only the first, "
                     "and Bob's own laptop all three. Each subscription is notified only when a record it sees arrives "
                     "(P§6, spec-gaps 145, 146).", ["P§6", "P§3", "P§8"], steps))

    f5 = rec("a-f5", seq=5, audience="family")
    w1 = rec("a-w1", seq=1, state="away", audience="work")
    f6 = rec("a-f6", seq=6, state="dnd", at=NOW + 2, audience="family")
    w0 = rec("a-w0", seq=1, state="dnd", at=NOW + 2, audience="work")
    f7 = rec("a-f7", seq=7, state="dnd", at=NOW + 5, audience="family")
    out.append(trace("presence-seq-and-interval-per-audience",
                     "seq and the publish interval run per (subject, device, audience): work's seq 1 after family's seq 5 "
                     "is not stale, family again 2 s later is rate-limited with 3 s left, work's seq 1 again is stale, "
                     "and family at 5 s is accepted (P§3, P§6, P§8).", ["P§3", "P§6", "P§8"], [
        bind(),
        step({"recv": f5}, []),
        step({"recv": w1}, []),
        adv(2),
        step({"recv": f6}, [{"send": {"type": "error", "to": BPH, "in_reply_to": f6["id"], "reason": "policy.rate-limited", "retry_after": 3}}]),
        step({"recv": w0}, [{"send": {"type": "error", "to": BPH, "in_reply_to": w0["id"], "reason": "presence.stale"}}]),
        adv(3),
        step({"recv": f7}, [], presence={BOB: {f"{BPH}/family": {"seq": 7, "state": "dnd", "expires_at": NOW + 305},
                                               f"{BPH}/work": {"seq": 1, "state": "away", "expires_at": NOW + 300}}}),
    ]))

    fam_only = rec("a-famonly", audience="family")
    work_watch = subscribe("a-workwatch", frm=CPH, grants=[grant("a-cw2", to=CAROL, audience="work")])
    fam_watch = subscribe("a-famwatch", grants=[fam])
    out.append(trace("presence-assertion-per-subscription",
                     "A device that publishes only to family counts in the assertion for a work subscriber, exactly as "
                     "a device that publishes nothing: Carol (work) sees 'available' from the relay and no record, Alice "
                     "(family) sees the record and an offline assertion. The record changes nothing in Carol's body, so "
                     "she is not notified (P§6, spec-gap 146).", ["P§6", "P§4", "§9.3"], [
        bind(),
        step({"recv": work_watch}, [notify(work_watch, 1, body("available"))]),
        step({"recv": fam_watch}, [notify(fam_watch, 1, body("available"))]),
        step({"recv": fam_only}, [notify(fam_watch, 2, body("offline", fam_only))]),
    ]))

    short = rec("a-short", ttl=60, audience="family")
    long_ = rec("a-long", state="away", ttl=300, audience="work")
    out.append(trace("presence-expiry-per-audience",
                     "Each record expires by itself: the family record's 60 s run out and only the family subscription "
                     "is notified (P§3, P§6).", ["P§3", "P§6"], [
        bind(),
        step({"recv": work_watch}, [notify(work_watch, 1, body("available"))]),
        step({"recv": fam_watch}, [notify(fam_watch, 1, body("available"))]),
        step({"recv": short}, [notify(fam_watch, 2, body("offline", short))]),
        step({"recv": long_}, [notify(work_watch, 2, body("offline", long_))]),
        adv(60, [notify(fam_watch, 3, body("available"))]),
    ]))

    out.append(trace("presence-grace-drops-every-audience",
                     "The unbind grace is per device: when it runs out, all the device's records go, and each subscription "
                     "that saw one is notified once (P§3, P§6).", ["P§3", "P§6", "P§8"], [
        bind(),
        step({"recv": work_watch}, [notify(work_watch, 1, body("available"))]),
        step({"recv": fam_watch}, [notify(fam_watch, 1, body("available"))]),
        step({"recv": short}, [notify(fam_watch, 2, body("offline", short))]),
        step({"recv": long_}, [notify(work_watch, 2, body("offline", long_))]),
        step({"relay": "unbind", "device": BPH, "identity": BOB}, []),
        adv(59),
        adv(1, in_order(notify(work_watch, 3, body("offline")), notify(fam_watch, 3, body("offline"))), presence={}),
    ]))

    share = grant("a-share", until=NOW + 600)
    shared = subscribe("a-shared", grants=[share])
    out.append(trace("presence-share-ends-at-valid-until",
                     "A share is a grant with a short valid_until: when the authority's clock reaches it, the subscription "
                     "it admitted ends with a terminated notify, reason policy.terminated, and a renewal presenting it is "
                     "refused (P§7, spec-gap 147).", ["P§7", "§9.3", "§12.9"], [
        bind(),
        step({"recv": shared}, [notify(shared, 1, body("available"))]),
        adv(599),
        adv(1, [notify(shared, 2, body("available"), "terminated", "policy.terminated")], subscriptions={}),
        step({"recv": (again := subscribe("a-again", grants=[share], at=NOW + 600))}, [blocked(again)]),
    ]))

    tie = grant("a-tie", until=NOW + 3600)
    tied = subscribe("a-tied", grants=[tie])
    out.append(trace("presence-lapse-before-share-end",
                     "A subscription that lapses at the instant its grant ends ends as lapsed: session.expired, not "
                     "policy.terminated (P§7, §9.3).", ["P§7", "§9.3"], [
        bind(),
        step({"recv": tied}, [notify(tied, 1, body("available"))]),
        adv(3600, [notify(tied, 2, body("available"), "terminated", "session.expired")], subscriptions={}),
    ]))

    rg = grant("a-rg")
    s1 = subscribe("a-rs1", grants=[rg])
    other = subscribe("a-rs3", frm=CPH, grants=[grant("a-rgc", to=CAROL)])
    out.append(trace("presence-revocation-ends-subscriptions",
                     "Bob's phone revokes the grant Alice subscribed with: her subscription ends at once, terminated with "
                     "policy.terminated; Carol's, under another grant, goes on; the revocation is not answered; and a "
                     "later subscribe presenting the grant is refused (P§7, §19.4, spec-gap 147).", ["P§7", "§19.4", "§9.3"], [
        bind(),
        step({"recv": s1}, [notify(s1, 1, body("available"))]),
        step({"recv": other}, [notify(other, 1, body("available"))]),
        step({"recv": revocation("a-rev", rg, at=NOW)},
             [notify(s1, 2, body("available"), "terminated", "policy.terminated")],
             subscriptions=subsnap(other, 1, CAROL, grant=other["claims"][0]["grant"]["id"])),
        step({"recv": (s4 := subscribe("a-rs4", grants=[rg], at=NOW + 1))}, [blocked(s4)]),
    ]))

    cg = grant("a-cg")
    cs = subscribe("a-cs", grants=[cg])
    out.append(trace("presence-revocation-by-another-identity",
                     "A revocation covers only grants issued by its signer's identity: Carol's phone naming Bob's grant id "
                     "ends nothing (P§7).", ["P§7", "§19.4"], [
        bind(),
        step({"recv": cs}, [notify(cs, 1, body("available"))]),
        step({"recv": revocation("a-crev", cg, frm=CPH)}, [], subscriptions=subsnap(cs, 1, ALICE, grant=cg["id"])),
    ]))

    pre = grant("a-pre")
    out.append(trace("presence-revoked-before-subscribe",
                     "A grant revoked before anyone subscribed with it admits nothing; until its valid_until passes the "
                     "authority keeps the revocation (P§7).", ["P§7", "§19.4"], [
        bind(),
        step({"recv": revocation("a-prerev", pre)}, []),
        adv(3600),
        step({"recv": (ps := subscribe("a-presub", grants=[pre], at=NOW + 3600))}, [blocked(ps)]),
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
