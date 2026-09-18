#!/usr/bin/env python3
"""Differential fuzzing: random traces through all three implementations, actual against actual.

Passing the conformance suite is not agreement (impl/docs/spec-gaps.md, spec-gaps 78, 80, 81): a
vector exercises one rule at a time, and two implementations can satisfy every vector and still
answer differently when two rules apply at once. This tool generates random, well-formed event
traces for the state machines and random rows for the table-shaped rules, runs them through the
Python harness, the Rust runner and `impl-ts`, and compares what each *computed* — there is no
expected value, only agreement.

    python3 impl/tools/fuzz.py                          # every target, seed 1, 200 probes each
    python3 impl/tools/fuzz.py --target hub,mailbox --seed 7 --count 500
    python3 impl/tools/fuzz.py --seed random --out /tmp/found   # keep reproducers

A divergence is shrunk (events are dropped while the three still disagree) and printed with what
each side answered at the first step that differs. It is never fixed here: it becomes a
hand-authored vector in `dsipvec/gen/`, with the expectation taken from the spec — or a spec-gap
when the spec does not say. Probes live in a temporary directory; nothing is written to
`impl/vectors`. Exit status 1 on any divergence or runner failure.

Build first: `cargo build -p dsip-cli` in `impl/`, `npm ci && npm run build` in `impl-ts/`.
"""
from __future__ import annotations

import argparse
import json
import random
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
NOW = 1760000000

# ---------------------------------------------------------------- the cast

ALICE, BOB, CAROL, MALLORY = ("did:web:alice.example", "did:web:example.com:users:bob", "did:web:carol.example",
                              "did:web:mallory.example")
A1, A2, B1, B2, C1, M1 = ("did:key:z6MkA1", "did:key:z6MkA2", "did:key:z6MkB1", "did:key:z6MkB2", "did:key:z6MkC1",
                          "did:key:z6MkM1")
DEVICES = {ALICE: [A1, A2], BOB: [B1, B2], CAROL: [C1], MALLORY: [M1]}
IDENTITY = {d: i for i, ds in DEVICES.items() for d in ds}
HUB_A, HUB_B, ROGUE, RELAY = ("did:web:mbx.alice.example", "did:web:mbx.bob.example", "did:web:rogue.example",
                              "did:web:relay.example.com")
G1, G2 = "MDFLNzQyU0cwMEhBWlpDS0MxMzFFQzBQR1M", "MDFLNzQyU0cwMDVCWTdRQzVDQkg4MUdSUVQ"
CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def ulid(n: int) -> str:
    """A well-formed ULID whose order follows `n` (what glare and update collisions compare)."""
    tail = ""
    for _ in range(16):
        tail = CROCKFORD[n % 32] + tail
        n //= 32
    return "01K742SG00" + tail


def cursor(n: int) -> str:
    return "c:%016x" % n


# ---------------------------------------------------------------- generators: (kind, check, context, events)
# Every generator returns well-formed events only: the question is what the machines *decide*, not
# how they fail on malformed input (that is the envelope pipeline's job, and the vectors cover it).


def gen_gap(r: random.Random):
    ev = []
    for _ in range(r.randint(3, 10)):
        if r.random() < 0.25:
            ev.append({"advance": r.choice([1, 100, 200, 299, 300])})
        else:
            ev.append({"item": {"seq": r.randint(1, 7), "class": r.choice(["application", "handshake"])}})
    ctx = {"component": "gap", "now": NOW, "contiguous": r.choice([0, 0, 2])}
    if r.random() < 0.3:
        ctx["gap_timeout"] = r.choice([5, 100])
    return "messaging", "gap-trace", ctx, ev


def gen_commit_retry(r: random.Random):
    """Only sequences a device can meet: an answer, then — when the machine would be syncing — a `synced`."""
    retried = ["mailbox.commit-conflict", "mailbox.stale-epoch", "mailbox.unknown-group", "mailbox.hub-draining", "mailbox.odd"]
    final = ["policy.blocked", "mailbox.quota-exceeded", "x-hubs.overloaded"]
    ev = []
    for _ in range(r.randint(1, 5)):
        reason = r.choice(retried + retried + final + [None])
        ev.append({"answer": {} if reason is None else {"reason": reason}})
        if reason is None or reason in final:
            break  # merged, or surfaced: the operation is over
        synced = {"still_needed": r.random() < 0.85}
        if reason == "mailbox.unknown-group" or r.random() < 0.2:
            synced["hub_moved"] = r.random() < 0.7
        ev.append({"synced": synced})
        if not synced["still_needed"] or (reason == "mailbox.unknown-group" and not synced.get("hub_moved")):
            break
    return "messaging", "commit-retry-trace", {"component": "commit-retry", "max_attempts": 3}, ev


def gen_hub_outage(r: random.Random):
    ids, ev, dep = [ulid(1), ulid(2), ulid(3)], [], []
    for _ in range(r.randint(3, 10)):
        x = r.random()
        if x < 0.3 and len(dep) < 3:
            dep.append(ids[len(dep)])
            ev.append({"deposit": {"id": dep[-1]}})
        elif x < 0.55 or not dep:
            ev.append({"advance": r.choice([1, 2, 4, 30, 60, 100])})
        else:
            i, c = r.choice(dep), r.random()
            if c < 0.2:
                ev.append({"no_answer": {"id": i}})
            else:
                why = {"reason": r.choice(["mailbox.hub-unreachable", "mailbox.hub-unreachable", "policy.blocked"])} if c < 0.7 else {}
                ev.append({"answer": {"id": i, **why}})
    return "messaging", "hub-outage-trace", {"component": "hub-outage", "now": NOW, "hub_timeout": r.choice([50, 150, 86400])}, ev


def gen_hub(r: random.Random):
    ev = []
    for n in range(r.randint(3, 9)):
        x = r.random()
        if x < 0.25:
            ev.append({"ack": {"identity": r.choice([ALICE, BOB, CAROL]), "seq": r.randint(1, 4),
                               **({"class": "welcome"} if r.random() < 0.25 else {})}})
        elif x < 0.3:
            ev.append({"restart": {}})
        else:
            ident = r.choice([ALICE, ALICE, BOB, BOB, CAROL, MALLORY])
            d = r.choice(DEVICES[ident])
            cls = r.choice(["application", "application", "handshake", "handshake", "handshake", "group-info", "ephemeral", "archive"])
            dep = {"id": ulid(100 + n), "device": d, "identity": ident, "class": cls, "digest": r.choice(["dup", "d%d" % r.randint(0, 50)])}
            if cls in ("application", "handshake", "group-info"):
                dep["epoch"] = r.choice([1, 1, 2, 2, 3])
            if cls == "ephemeral":
                dep["expires_at"] = r.choice([NOW - 1, NOW + 10])
            if cls == "handshake" and r.random() < 0.8:
                c, y = {"adds": [], "removes": []}, r.random()
                if y < 0.2:
                    c["adds"] = [{"identity": CAROL, "device": C1}]
                elif y < 0.3:
                    c["adds"] = [{"identity": BOB, "device": B2}]
                elif y < 0.4:
                    c["removes"] = [{"identity": BOB, "device": B1}]
                elif y < 0.5:
                    c["removes"] = [{"identity": ALICE, "device": A1, **({"delegation_valid": False} if r.random() < 0.5 else {})}]
                elif y < 0.6:
                    c.update({"external": True, "adds": [{"identity": ident, "device": d}]})
                elif y < 0.65:
                    c["moves_to"] = HUB_B
                elif y < 0.7:
                    c["valid"] = False
                dep["commit"] = c
            ev.append({"deposit": dep})
    ctx = {"component": "hub", "hub": HUB_A, "group": G1, "kind": "group", "now": NOW, "epoch": 2,
           "roster": {ALICE: [A1, A2], BOB: [B1]}}
    return "messaging", "hub-trace", ctx, ev


def gen_mailbox(r: random.Random):
    grant_id, sent = ulid(900), ulid(901)
    ev = []
    for n in range(r.randint(4, 12)):
        x, g, i = r.random(), r.choice([G1, G1, G2]), ulid(200 + n)
        if x < 0.30:
            cls = r.choice(["application", "application", "handshake", "group-info", "ephemeral"])
            d = {"id": i, "from": r.choice([HUB_A, HUB_A, HUB_A, HUB_B, ROGUE]), "recipient": BOB, "group": g,
                 "seq": None if cls in ("group-info", "ephemeral") else r.randint(1, 5), "class": cls}
            if cls == "ephemeral" and r.random() < 0.5:
                d["expires_at"] = r.choice([NOW - 1, NOW + 500])
            ev.append({"hub_deposit": d})
        elif x < 0.42:
            grant = r.choice([None, {"id": grant_id, "from": BOB, "to": r.choice([CAROL, ALICE]),
                                     "scope": r.choice([["dsip.message"], ["dsip.invite"], ["dsip.subscribe"]]),
                                     "valid_until": r.choice([NOW - 10000, NOW + 86400])}])
            ev.append({"welcome": {"id": i, "from": C1, "adder_identity": r.choice([CAROL, CAROL, BOB]),
                                   "recipient": r.choice([BOB, BOB, BOB, ALICE]), "group": g, "hub": HUB_A, "grant": grant,
                                   "digest": r.choice(["w1", "w2"])}})
        elif x < 0.52:
            y = r.random()
            if y < 0.2:
                c = {"id": i, "device": B1, "revoked_grants": [grant_id]}
            elif y < 0.35:
                c = {"id": i, "device": B1, "introductions_sent": [sent]}
            else:
                grp = {"group": g, "state": r.choice(["joined", "joined", "left"])}
                if r.random() < 0.5:
                    grp.update({"hub": HUB_B, "handover_seq": r.randint(1, 3)})
                c = {"id": i, "device": B1, "groups": [grp]}
            ev.append({"config": c})
        elif x < 0.64:
            s = {"id": i, "device": r.choice([B1, B2]), "since": r.choice([None, None, cursor(1), cursor(2), cursor(9)])}
            if r.random() < 0.5:
                s["live"] = True
            if r.random() < 0.4 and s["since"]:
                s["ack_through"] = s["since"]
            if r.random() < 0.2:
                s["limit"] = 1
            ev.append({"sync": s})
        elif x < 0.74:
            ev.append({"advance": r.choice([1, 100, 299, 300, 301, 604800])})
        elif x < 0.78:
            ev.append({"restart": {}})
        elif x < 0.84:
            ev.append({"archive": {"id": i, "device": r.choice([B1, B2]), "ref_group": G1, "ref_seq": r.randint(1, 2)}})
        elif x < 0.90:
            ev.append({"forward": {"id": i, "device": r.choice([B1, C1]), "identity": r.choice([BOB, BOB, CAROL]), "group": g,
                                   "to": r.choice([HUB_A, HUB_B])}})
        elif x < 0.94:
            ev.append({"kp_fetch": {"id": i, "from": C1, "from_identity": r.choice([CAROL, BOB]), "target": BOB, "grant": None,
                                    **({"successor_of": g} if r.random() < 0.4 else {})}})
        else:
            kind = r.choice(["introduction", "introduction", "grant", "grant"])
            fc = {"id": i, "from": C1, "sender_identity": r.choice([CAROL, ALICE]),
                  "recipient": r.choice([BOB, BOB, "did:web:nobody.example"]), "kind": kind, "expires_at": NOW + r.choice([30, 600])}
            if kind == "grant" and r.random() < 0.6:
                fc["session"] = r.choice([sent, ulid(999)])
            ev.append({"first_contact": fc})
    ctx = {"component": "mailbox", "mailbox": HUB_B, "owner": BOB, "serves": [BOB], "devices": [B2, B1], "now": NOW,
           "mode": r.choice(["sync", "sync", "queue"]), "admit": r.choice(["grant", "grant", "grant", "open"]),
           "pending_group_ttl": 604800, "pending_group_max_items": 2,
           "groups": r.choice([{}, {G1: {"hub": HUB_A, "state": "joined"}}, {G1: {"hub": HUB_A, "state": "joined"}}]),
           "key_packages": r.choice([{}, {B1: {"one_time": 1, "last_resort": True}, B2: {"one_time": 0, "last_resort": False}}]),
           "intro_limit": 2, "intro_window": 3600, "inbox_cap": 3}
    return "messaging", "mailbox-trace", ctx, ev


def gen_resume(r: random.Random):
    ev, n = [], 0
    for _ in range(r.randint(2, 7)):
        x = r.random()
        if x < 0.55:
            items = []
            for _ in range(r.randint(1, 4)):
                n += 1
                cls = r.choice(["application", "application", "application", "welcome", "group-info"])
                it = {"cursor": cursor(n), "class": cls, "group": r.choice([G1, G1, G2])}
                if cls == "application":
                    it["seq"] = r.randint(1, 6)
                if cls == "welcome" and r.random() < 0.3:
                    it["sibling"] = True
                items.append(it)
            body = {"items": items}
            if r.random() < 0.2:
                body["crash_at"] = r.choice(items)["cursor"]
            ev.append({"items": body})
        elif x < 0.65:
            ev.append({"sent": {"group": G1, "seq": r.randint(1, 6)}})
        elif x < 0.72:
            ev.append({"rejoined": {"group": G1, "seq": r.randint(1, 6)}})
        else:
            ev.append({r.choice(["sync", "restart", "cursor_invalid"]): {}})
    return "messaging", "resume-trace", {"component": "resume", "cursor": None, "groups": {}, "joined": []}, ev


def gen_history(r: random.Random):
    keys, ev, n = [ulid(500), ulid(501)], [], 0
    for _ in range(r.randint(3, 9)):
        x, seq = r.random(), r.randint(1, 5)
        obj = r.choice([None, None, None, "receipt", "call-event"])
        ident = "%s%d" % ("m" if obj is None else obj[0], seq)
        extra = {} if obj is None else {"object": obj}
        if x < 0.35:
            n += 1
            ev.append({"archive": {"cursor": cursor(n), "akid": r.choice(keys), "group": G1, "seq": seq, "id": ident, **extra}})
        elif x < 0.5:
            k = r.choice(keys)
            ev.append({"archive_key": {"akid": k, "created_at": NOW + (60 if k == keys[1] else 0)}})
        elif x < 0.75:
            ev.append({"mls": {"group": G1, "seq": seq, "epoch": r.randint(1, 4), "id": "m%d" % seq}})  # content only (README)
        elif x < 0.9:
            ev.append({"sent": {"group": G1, "seq": seq, "id": ident, **extra}})
        else:
            ev.append({"joined": {"group": G1, "epoch": r.randint(1, 4)}})
    ctx = {"component": "history", "keys": r.choice([[], [{"akid": keys[0], "created_at": NOW}]]), "joined": {}}
    return "messaging", "history-trace", ctx, ev


def gen_successor(r: random.Random):
    import base64
    gid = lambda u: base64.urlsafe_b64encode(u.encode()).decode().rstrip("=")
    cands = [gid(ulid(n)) for n in (610, 620, 630)] + ["bm90LWEtdWxpZA"]
    pred, roster = G1, [ALICE, BOB, CAROL]
    member = r.random() < 0.75
    ev, created, seen = [], False, False
    for _ in range(r.randint(2, 6)):
        if r.random() < 0.7:
            w = {"group": r.choice(cands), "successor_of": r.choice([pred, pred, G2]), "creator": r.choice([BOB, CAROL, MALLORY]),
                 "roster": r.choice([roster, roster, [ALICE, BOB], [ALICE, BOB, MALLORY]])}
            seen = seen or (member and w["successor_of"] == pred and w["creator"] != MALLORY and MALLORY not in w["roster"]
                            and w["group"] != cands[3])
            ev.append({"welcome": w})
        else:
            ev.append({"create": {"predecessor": r.choice([pred, pred, G2])}})
            # the device creates the group only when the machine said `create`: a member, with no successor yet, once
            if ev[-1]["create"]["predecessor"] == pred and member and not seen and not created:
                created = True
                ev.append({"created": {"group": r.choice(cands[:3]), "successor_of": pred}})
                seen = True
    return "messaging", "successor-trace", {"component": "successor", "groups": {pred: roster} if member else {}}, ev


def gen_client(r: random.Random):
    ids = [ulid(700 + k) for k in range(4)]
    me = r.choice([ALICE, BOB])
    ev, seq = [], 0
    for _ in range(r.randint(3, 9)):
        x = r.random()
        if x < 0.45:
            items = []
            for _ in range(r.randint(1, 3)):
                seq += 1
                if r.random() < 0.55:
                    items.append({"seq": seq, "object": {"object": "content", "id": r.choice(ids), "sender": r.choice([ALICE, BOB]),
                                                        "kind": r.choice(["text", "text", "audio"])}})
                else:
                    kind = r.choice(["delivered", "read", "played"])
                    body = {"through": r.choice(ids)} if kind == "read" else {"targets": r.sample(ids, r.randint(1, 2))}
                    items.append({"seq": seq, "object": {"object": "receipt", "kind": kind, "sender": r.choice([ALICE, BOB, CAROL]),
                                                        "sent_at": NOW + seq, **body}})
            ev.append({r.choice(["sync", "sync", "sync", "restore"]): {"items": items}})
        elif x < 0.6:
            ev.append({"read": {"through": r.choice(ids)}})
        elif x < 0.7:
            ev.append({"play": {"id": r.choice(ids)}})
        elif x < 0.8:
            ev.append({"activity": {"activity": r.choice(["typing", "uploading"]), "state": r.choice(["active", "active", "stopped"])}})
        elif x < 0.9:
            ev.append({"activity_in": {"sender": r.choice([ALICE, CAROL]), "activity": r.choice(["typing", "uploading"]),
                                       "state": r.choice(["active", "active", "stopped"]), "expires_at": NOW + r.choice([-5, 5, 10, 20])}})
        else:
            ev.append({"advance": r.choice([1, 3, 5, 6, 11])})
    ctx = {"component": "client", "me": me, "device": DEVICES[me][0], "now": NOW, "member_identities": r.choice([2, 2, 33]),
           "policy": {k: r.random() < 0.6 for k in ("delivered", "read", "played", "activity")}}
    return "messaging", "client-trace", ctx, ev


REASONS = ["user.declined", "user.no-answer", "endpoint.busy", "endpoint.unavailable", "session.glare", "policy.blocked",
           "user.stepped-out", "x-cc.queue-full"]


def gen_endpoint(r: random.Random):
    """One endpoint (Alice's phone), two possible sessions each way, every local and remote event."""
    out_ids, in_ids, upd = [ulid(10), ulid(30)], [ulid(20), ulid(5)], [ulid(40 + k) for k in range(4)]
    intro_ids, grant_ids = [ulid(50), ulid(51)], [ulid(60), ulid(61)]
    sessions = out_ids + in_ids
    ev, clock, counter = [], NOW, [1000]
    fresh_in = list(in_ids)  # an invite id arrives once: the replay stage drops a repeated id before the engine sees it (§12.9)

    def mid() -> str:
        counter[0] += 1
        return ulid(counter[0])

    for _ in range(r.randint(3, 12)):
        x, sid = r.random(), r.choice(sessions)
        peer = r.choice([B1, B1, B2, C1])
        if x < 0.12:
            ev.append({"local": "place_call", "session": r.choice(out_ids), "to": r.choice([BOB, BOB, B1])})
        elif x < 0.22 and fresh_in:
            # a received message has passed the envelope pipeline, so an invite is never expired on arrival (README, `recv`);
            # it may expire later, before the user is alerted
            ev.append({"recv": {"type": "invite", "id": fresh_in.pop(r.randrange(len(fresh_in))), "from": peer, "to": ALICE,
                                "expires_at": clock + r.choice([3, 30, 30]), **({"grant": r.choice(grant_ids)} if r.random() < 0.2 else {})}})
        elif x < 0.32:
            st = r.choice(["ringing", "ringing", "trying", "queued", "forwarded", "levitating"])
            m = {"type": "progress", "id": mid(), "from": peer, "session": sid, "status": st}
            if st == "ringing" and r.random() < 0.5:
                m["ring_timeout"] = r.choice([10, 60, 500])
            if st == "queued":
                m["queue_timeout"] = r.choice([30, 5000])
            ev.append({"recv": m})
        elif x < 0.42:
            m = {"type": "answer", "id": mid(), "from": peer, "session": sid, "answered_by": r.choice(["user", "screening", "butler"])}
            if r.random() < 0.3:
                m["in_reply_to"] = r.choice(upd)
            ev.append({"recv": m})
        elif x < 0.50:
            m = {"type": "reject", "id": mid(), "from": peer, "session": r.choice(sessions + intro_ids), "reason": r.choice(REASONS)}
            if r.random() < 0.3:
                m["in_reply_to"] = r.choice(upd)
            ev.append({"recv": m})
        elif x < 0.57:
            ev.append({"recv": {"type": r.choice(["cancel", "bye"]), "id": mid(), "from": peer, "session": sid,
                                "reason": r.choice(["user.cancelled", "session.timeout", "session.answered-elsewhere", "user.hangup"])}})
        elif x < 0.62:
            ev.append({"recv": {"type": "error", "id": mid(), "from": r.choice([RELAY, peer]), "session": sid,
                                "reason": r.choice(["transport.no-response", "policy.rate-limited"])}})
        elif x < 0.67:
            upd.append(mid())  # a received update has an id of its own; later replies may name it
            ev.append({"recv": {"type": "update", "id": upd[-1], "from": peer, "session": sid,
                                **({"answered_by": "user"} if r.random() < 0.3 else {})}})
        elif x < 0.71:
            ev.append({"recv": {"type": "info", "id": mid(), "from": peer, "session": sid,
                                "about": r.choice(["transport:webrtc", "media:dtmf", "x-vendor:thing"])}})
        elif x < 0.76:
            ev.append({"local": r.choice(["cancel", "hangup", "decline", "info"]), "session": sid})
        elif x < 0.81:
            ev.append({"local": "alert", "session": sid, **({"ring_timeout": 45} if r.random() < 0.3 else {})})
        elif x < 0.85:
            ev.append({"local": "accept", "session": sid, "answered_by": r.choice(["user", "screening"])})
        elif x < 0.88:
            ev.append({"local": "auto_reject", "session": sid, "reason": r.choice(["endpoint.busy", "policy.blocked"])})
        elif x < 0.92:
            y = r.random()
            if y < 0.5:
                ev.append({"local": "update", "session": sid, "id": r.choice(upd)})
            elif y < 0.8:
                ev.append({"local": "answer_update", "session": sid, "in_reply_to": r.choice(upd)})
            else:
                ev.append({"local": "reject_update", "session": sid, "in_reply_to": r.choice(upd), "reason": "media.unsupported"})
        elif x < 0.96:
            y = r.random()
            if y < 0.3:
                ev.append({"recv": {"type": "introduction", "id": r.choice(intro_ids), "from": C1, "to": ALICE, "purpose": "hi",
                                    **({"contact_token": "tok"} if r.random() < 0.4 else {})}})
            elif y < 0.45:
                ev.append({"local": "issue_token", "token": "tok", "grant_id": grant_ids[1]})
            elif y < 0.6:
                ev.append({"local": "grant", "introduction": r.choice(intro_ids), "id": grant_ids[0], "scope": ["dsip.invite"],
                           "valid_until": NOW + r.choice([-10, 100000])})
            elif y < 0.7:
                ev.append({"local": "reject_introduction", "introduction": r.choice(intro_ids), "reason": "user.declined"})
            elif y < 0.8:
                ev.append({"local": "revoke", "grant": r.choice(grant_ids)})
            elif y < 0.9:
                ev.append({"local": "introduce", "id": intro_ids[0], "to": BOB, "purpose": "hello"})
            else:
                ev.append({"recv": {"type": "grant", "id": grant_ids[0], "from": B1, "session": r.choice(intro_ids),
                                    "scope": ["dsip.invite"], "valid_until": NOW + 100000}})
        else:
            ev.append({"advance": r.choice([1, 5, 15, 30, 120, 121])})
            clock += ev[-1]["advance"]
    ctx = {"component": "endpoint", "self": {"device": A1, "identity": ALICE}, "identities": dict(IDENTITY), "start": NOW}
    if r.random() < 0.3:
        ctx["policy"] = {"first_contact_required": True, "allow": r.choice([[], [BOB]])}
    snapshot = {"sessions": {s: {} for s in sessions}, "contacts": {}}
    return "state", None, ctx, [(e, snapshot) for e in ev]


def gen_relay(r: random.Random):
    """Every message carries `to`, as every real envelope does (the schemas require it)."""
    sids = [ulid(10), ulid(11)]
    ev, counter = [], [1000]

    def mid() -> str:
        counter[0] += 1
        return ulid(counter[0])

    for _ in range(r.randint(3, 10)):
        x, sid = r.random(), r.choice(sids)
        if x < 0.2:
            ev.append({"relay": r.choice(["bind", "bind", "unbind"]), "device": r.choice([B1, B2, A1]), "identity": None})
            ev[-1]["identity"] = IDENTITY[ev[-1]["device"]]
        elif x < 0.35:
            ev.append({"recv": {"type": "invite", "id": sid, "from": A1, "to": r.choice([BOB, BOB, "did:web:nobody.example"]),
                                "expires_at": NOW + r.choice([30, 30, 2])}})
        elif x < 0.42:
            ev.append({"relay": "invite", "session": sid, "from": A1, "to": BOB, "legs": [B1, B2]})
        elif x < 0.52:
            ev.append({"recv": {"type": "progress", "id": mid(), "from": r.choice([B1, B2]), "session": sid, "to": A1, "status": "ringing"}})
        elif x < 0.62:
            ev.append({"recv": {"type": "answer", "id": mid(), "from": r.choice([B1, B2]), "session": sid, "to": A1, "answered_by": "user"}})
        elif x < 0.72:
            ev.append({"recv": {"type": "reject", "id": mid(), "from": r.choice([B1, B2]), "session": sid, "to": A1,
                                "reason": r.choice(REASONS)}})
        elif x < 0.8:
            ev.append({"recv": {"type": "cancel", "id": mid(), "from": A1, "session": sid,
                                "reason": r.choice(["user.cancelled", "session.answered-elsewhere"]),
                                "to": r.choice([BOB, BOB, B1])}})
        elif x < 0.86:
            ev.append({"relay": "leg_expired", "session": sid, "leg": r.choice([B1, B2])})
        elif x < 0.92:
            ev.append({"recv": {"type": "introduction", "id": mid(), "from": C1,
                                "to": r.choice([BOB, "did:web:nobody.example"]), "purpose": "hi", "expires_at": NOW + 600}})
        elif x < 0.96:
            ev.append({"recv": {"type": r.choice(["bye", "info", "update"]), "id": mid(), "from": A1, "session": sid,
                                "to": r.choice([B1, B2]), "reason": "user.hangup", "about": "transport:webrtc", "expires_at": NOW + 60}})
        else:
            ev.append({"advance": r.choice([1, 5, 31, 700])})
    ctx = {"component": "relay", "start": NOW}
    if r.random() < 0.3:
        ctx["offline_retention_s"] = 10
    snapshot = {"attempts": {s: {} for s in sids}, "inbox": {}}
    return "state", None, ctx, [(e, snapshot) for e in ev]


def gen_deposit_fields(r: random.Random):
    """One table row: a deposit class with one extra field (spec-gap 80)."""
    mls, blob = "bWxz", {"uri": "https://mbx.alice.example/blobs/" + "9f" * 32, "sha256": "9f" * 32, "size": 10}
    base = {"dsip": {"core": "1.0", "min_core": "1.0", "profiles": ["messaging/1.0"], "extensions": [], "critical": []},
            "type": "deposit", "id": ulid(1), "from": A1, "to": HUB_A, "issued_at": NOW, "expires_at": NOW + 30}
    classes = {
        "handshake": {"group": G1, "mls": mls}, "application": {"group": G1, "mls": mls},
        "welcome": {"group": G1, "mls": mls, "hub": {"did": HUB_A, "uri": "wss://mbx.alice.example/dsip"}},
        "group-info": {"group": G1, "mls": mls}, "ephemeral": {"group": G1, "sealed": "c2VhbGVk"},
        "archive": {"group": G1, "archive": "YXJj", "akid": ulid(2), "ref_group": G1, "ref_seq": 1},
    }
    extras = {"welcome": mls, "group_info": mls, "ratchet_tree_blob": blob, "grants": ["eyJ.g.s"], "seq": 5, "blobs": [blob],
              "recipient": BOB, "hub": {"did": HUB_A, "uri": "wss://mbx.alice.example/dsip"}, "origin": "eyJ.o.s", "successor_of": G2,
              "handover_seq": 3, "sealed": "c2VhbGVk", "archive": "YXJj", "akid": ulid(2), "ref_group": G1, "ref_seq": 1, "mls": mls}
    cls = r.choice(list(classes))
    p = {**base, "class": cls, **classes[cls]}
    for f in r.sample(list(extras), r.randint(0, 2)):
        p.setdefault(f, extras[f])
    return "messaging", "message", {}, {"payload": p}


def gen_gateway_reason(r: random.Random):
    if r.random() < 0.5:
        inp = {"check": "reason-inbound", "phase": r.choice(["pre-answer", "active", "transport"])}
        if r.random() < 0.7:
            inp["sip_status"] = r.choice([403, 404, 408, 410, 415, 480, 484, 486, 487, 488, 500, 502, 503, 504, 600, 603, 604, 606, 699])
        if r.random() < 0.6:
            inp["q850"] = r.choice([1, 16, 17, 18, 19, 20, 21, 22, 28, 31, 34, 38, 41, 42, 47, 63, 65, 79, 99, 102])
        if r.random() < 0.15:
            inp["moved_to"] = "tel:+15557654321"
        return "gateway", None, {}, inp
    tokens = ["user.declined", "user.blocked", "user.no-answer", "user.cancelled", "user.hangup", "endpoint.busy", "endpoint.unavailable",
              "endpoint.capability", "identity.not-in-service", "identity.moved", "identity.suspended", "identity.unknown",
              "session.expired", "session.timeout", "session.failed", "session.cancelled", "media.unsupported", "media.failed",
              "policy.blocked", "policy.rate-limited", "policy.terminated", "transport.unknown-recipient", "transport.no-response",
              "gateway.unreachable", "gateway.mapped", "mailbox.quota-exceeded", "user.stepped-out", "endpoint.on-fire",
              "identity.odd", "media.odd", "policy.odd", "transport.odd", "gateway.odd", "x-cc.queue-full"]
    return "gateway", None, {}, {"check": "reason-outbound", "reason": r.choice(tokens), "phase": r.choice(["pre-answer", "active"])}


TARGETS = {
    "gap": gen_gap, "commit-retry": gen_commit_retry, "hub-outage": gen_hub_outage, "resume": gen_resume, "history": gen_history,
    "successor": gen_successor, "client": gen_client, "hub": gen_hub, "mailbox": gen_mailbox, "endpoint": gen_endpoint,
    "relay": gen_relay, "deposit-fields": gen_deposit_fields, "gateway-reason": gen_gateway_reason,
}

# Targets where the implementations are known to differ and the difference is a protocol decision, not a bug
# (impl/docs/spec-gaps.md). `--target all` leaves them out so CI stays meaningful; name them to run them.
OPEN = {
    "relay": "session traffic for a session the relay never saw an invite for: dropped, or routed by `to` (spec-gap 82)",
    "resume": "a group's first sequenced item: the position it starts counting from, or one seq seen beyond a gap (spec-gap 83)",
}

# ---------------------------------------------------------------- probes


def probe(name: str, kind: str, check, ctx: dict, body) -> dict:
    """A probe is an ordinary vector whose `expect` is a placeholder: only the runners' actual results are compared."""
    v = {"vector": f"{kind}/{name}", "format": 1, "kind": kind, "description": "generated probe", "spec_ref": ["—"], "context": ctx}
    if isinstance(body, dict):  # a table row
        v["input"] = {**({"check": check} if check else {}), **body}
        v["expect"] = {}
    elif kind == "state":  # per-step expectations, which also name the snapshot members to report
        v["input"] = {"steps": [{"event": e, "expect": {"emit": [], **snap}} for e, snap in body]}
        v["expect"] = {}
    else:
        v["input"] = {"check": check, "steps": [{"event": e} for e in body]}
        v["expect"] = {"steps": [{"emit": [], "state": {}} for _ in body]}
    return v


def events_of(v: dict) -> list:
    return v["input"].get("steps", [])


def without(v: dict, i: int) -> dict:
    w = json.loads(json.dumps(v))
    del w["input"]["steps"][i]
    if "steps" in w["expect"]:
        del w["expect"]["steps"][i]
    return w


# ---------------------------------------------------------------- runners

RUNNERS = {
    "python": lambda d, out: [sys.executable, str(REPO / "impl/tools/run_vectors.py"), "--dir", str(d), "--json", str(out)],
    "rust": lambda d, out: ["cargo", "run", "-q", "-p", "dsip-cli", "--", "vectors", "run", "--dir", str(d), "--json", str(out)],
    "typescript": lambda d, out: ["node", str(REPO / "impl-ts/dist/run-vectors.js"), "--dir", str(d), "--json", str(out)],
}


def prune(x):
    """Snapshots of things that do not exist are reported as null by one runner and left out by another."""
    if isinstance(x, dict):
        return {k: prune(v) for k, v in x.items() if v is not None or k in ("cursor", "current_akid", "down_for", "moved_to",
                                                                             "outstanding_update", "next", "since", "selected",
                                                                             "source", "winner", "outcome")}
    return [prune(v) for v in x] if isinstance(x, list) else x


def run_all(vectors: list[dict], which: list[str]) -> dict[str, dict]:
    """Every probe through every runner: {runner: {vector id: what it computed}}."""
    with tempfile.TemporaryDirectory(prefix="dsip-fuzz-") as td:
        root = Path(td) / "vectors"
        for v in vectors:
            kind, name = v["vector"].split("/")
            (root / kind).mkdir(parents=True, exist_ok=True)
            (root / kind / f"{name}.json").write_text(json.dumps(v))
        results = {}
        for name in which:
            out = Path(td) / f"{name}.json"
            p = subprocess.run(RUNNERS[name](root, out), cwd=REPO / "impl", capture_output=True, text=True)
            if not out.exists():
                raise SystemExit(f"{name} runner produced no results:\n{p.stdout[-2000:]}\n{p.stderr[-2000:]}")
            raw = json.loads(out.read_text())
            results[name] = {k: prune(r.get("steps", r.get("actual"))) for k, r in raw.items()}
            for k, a in results[name].items():
                if isinstance(a, dict) and "steps" in a:
                    results[name][k] = a["steps"]
        return results


def disagreement(results: dict[str, dict], vid: str):
    answers = {n: r.get(vid) for n, r in results.items()}
    first = next(iter(answers.values()))
    return None if all(a == first for a in answers.values()) else answers


# Targets whose traces are a strict dialogue (answer, then synced): dropping one event makes a trace no device can meet.
NO_SHRINK = ("probe-commit-retry-",)


def shrink(v: dict, which: list[str], budget: int = 40) -> dict:
    """Drop events while the runners still disagree (greedy, one at a time)."""
    if any(tag in v["vector"] for tag in NO_SHRINK):
        return v
    i = len(events_of(v)) - 1
    while i >= 0 and budget > 0 and len(events_of(v)) > 1:
        w = without(v, i)
        budget -= 1
        if disagreement(run_all([w], which), w["vector"]):
            v = w
        i -= 1
    return v


def report(v: dict, answers: dict) -> None:
    print(f"\n[DIVERGE] {v['vector']}   context: {json.dumps(v['context'])[:400]}")
    seqs = [a for a in answers.values() if isinstance(a, list)]
    if len(seqs) == len(answers) and events_of(v):
        n = next((k for k in range(min(map(len, seqs))) if len({json.dumps(a[k], sort_keys=True) for a in seqs}) > 1), 0)
        for k, step in enumerate(events_of(v)[: n + 1]):
            print(f"   {'→' if k == n else ' '} {json.dumps(step['event'])[:300]}")
        for name, a in answers.items():
            print(f"     {name:11s}{json.dumps(a[n] if n < len(a) else None)[:600]}")
    else:
        print(f"     input      {json.dumps(v['input'])[:500]}")
        for name, a in answers.items():
            print(f"     {name:11s}{json.dumps(a)[:500]}")


def summarize(bad: list) -> None:
    """Group divergences by the kind of event they occur at and the head of what each runner emitted there."""
    groups: dict[tuple, list] = {}
    for v, answers in bad:
        seqs = list(answers.values())
        if not all(isinstance(a, list) for a in seqs) or not events_of(v):
            key = (json.dumps(v["input"])[:80],) + tuple(json.dumps(a)[:70] for a in seqs)
        else:
            n = next((k for k in range(min(map(len, seqs))) if len({json.dumps(a[k], sort_keys=True) for a in seqs}) > 1), 0)
            e = events_of(v)[n]["event"]
            verb = next(iter(e))
            body = e[verb]
            what = body.get("type", "") if isinstance(body, dict) else (body if isinstance(body, str) else "")
            head = lambda a: json.dumps((a[n].get("emit") or [{}])[0])[:90] + (" +state" if len({json.dumps(x[n].get("emit")) for x in seqs}) == 1 else "")
            key = (f"{verb} {what}",) + tuple(head(a) for a in seqs)
        groups.setdefault(key, []).append(v["vector"])
    for key, ids in sorted(groups.items(), key=lambda kv: -len(kv[1]))[:25]:
        print(f"  {len(ids):4d} × at `{key[0]}`   e.g. {ids[0]}")
        for name, ans in zip(("python", "rust", "typescript"), key[1:]):
            print(f"           {name:11s}{ans}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--target", default="all", help="comma-separated: " + ", ".join(TARGETS) +
                    " (default: all, which leaves out the open decisions: " + ", ".join(OPEN) + ")")
    ap.add_argument("--seed", default="1", help="integer, or `random`")
    ap.add_argument("--count", type=int, default=200, help="probes per target")
    ap.add_argument("--runners", default="python,rust,typescript")
    ap.add_argument("--out", help="directory to keep shrunk reproducers in")
    ap.add_argument("--max-reports", type=int, default=5, help="divergences to shrink and print per target")
    ap.add_argument("--summary", action="store_true",
                    help="do not shrink: group the divergences by the event they happen at and what each side answered")
    args = ap.parse_args()

    seed = random.SystemRandom().randrange(1 << 31) if args.seed == "random" else int(args.seed)
    targets = [t for t in TARGETS if t not in OPEN] if args.target == "all" else args.target.split(",")
    for t in targets:
        if t not in TARGETS:
            raise SystemExit(f"unknown target {t}; choose from: {', '.join(TARGETS)}")
        if t in OPEN:
            print(f"note: {t} is an open decision — {OPEN[t]}")
    which = args.runners.split(",")
    print(f"fuzz: seed {seed}, {args.count} probes per target, runners {', '.join(which)}")

    probes, by_target = [], {}
    for t in targets:
        r = random.Random(f"{seed}/{t}")
        for k in range(args.count):
            kind, check, ctx, body = TARGETS[t](r)
            if isinstance(body, list) and not body:
                continue
            v = probe(f"probe-{t}-{k}", kind, check, ctx, body)
            probes.append(v)
            by_target.setdefault(t, []).append(v)
    results = run_all(probes, which)

    total = 0
    for t in targets:
        bad = [(v, a) for v in by_target.get(t, []) if (a := disagreement(results, v["vector"]))]
        total += len(bad)
        print(f"{t:15s}{len(by_target.get(t, [])):5d} probes, {len(bad)} divergences")
        if args.summary:
            summarize(bad)
            continue
        for v, _ in bad[: args.max_reports]:
            small = shrink(v, which) if events_of(v) else v
            report(small, disagreement(run_all([small], which), small["vector"]) or {})
            if args.out:
                Path(args.out).mkdir(parents=True, exist_ok=True)
                (Path(args.out) / (small["vector"].replace("/", "-") + ".json")).write_text(json.dumps(small, indent=1))
    print(f"\n{len(probes)} probes, {total} divergences" + (f" — reproduce with --seed {seed}" if total else ""))
    return 1 if total else 0


if __name__ == "__main__":
    if shutil.which("node") is None or shutil.which("cargo") is None:
        print("fuzz.py needs node and cargo on PATH", file=sys.stderr)
        sys.exit(2)
    sys.exit(main())
