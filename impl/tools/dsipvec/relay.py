"""§12.7 forking relay attempt tracker — Python reference for `state/relay-*` traces.

The relay tracks which legs an invite was delivered to and which have
terminated, delivers `cancel` per-leg, and signals the attempt outcome with
the most informative reason when the last leg terminates without an answer.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# §12.7 rule 6 preference order; anything else ranks after these, first-seen first.
REASON_RANK = ["user.declined", "user.no-answer", "endpoint.busy", "endpoint.unavailable"]
TERMINAL = ("answered", "rejected", "expired", "cancelled")


@dataclass
class Attempt:
    session: str
    initiator: str
    identity: str
    legs: dict[str, str] = field(default_factory=dict)          # device -> delivered|answered|rejected|expired|cancelled
    reasons: dict[str, str] = field(default_factory=dict)       # device -> reject reason
    outcome: str | None = None                                  # None | answered | rejected | cancelled
    order: list[str] = field(default_factory=list)

    def snapshot(self) -> dict:
        return {"legs": dict(self.legs), "outcome": self.outcome}


class Relay:
    """Spec: §12.7 rules 3 and 6, §13.2 delivery semantics."""

    def __init__(self, ctx: dict):
        self.now = ctx.get("start", 0)
        self.attempts: dict[str, Attempt] = {}
        self.out: list[dict] = []
        self.bindings: dict[str, set[str]] = {}        # identity → bound devices (§13.2); a key = "known" identity
        self.devices: dict[str, str] = {}              # device → identity, for every device ever bound
        self.inbox: dict[str, list[dict]] = {}         # identity/device → queued envelopes (§13.3 store-and-forward)
        self.retention: int = ctx.get("offline_retention_s", 86400)
        self.invites: dict[str, dict] = {}             # session → invite message (for legs added mid-attempt)

    def emit(self, e: dict) -> None:
        self.out.append(e)

    def step(self, event: dict) -> list[dict]:
        self.out = []
        if "advance" in event:
            self.now += event["advance"]
            self.expire_queues()
        elif "relay" in event:
            self.relay_event(event)
        elif "recv" in event:
            self.recv(event["recv"])
        else:
            raise ValueError(f"unknown relay event {event}")
        return self.out

    def relay_event(self, ev: dict) -> None:
        if ev["relay"] == "invite":
            a = Attempt(ev["session"], ev["from"], ev["to"])
            for leg in ev["legs"]:
                a.legs[leg] = "delivered"
                self.emit({"deliver": {"leg": leg, "type": "invite"}})
            self.attempts[a.session] = a
        elif ev["relay"] == "bind":
            device, identity = ev["device"], ev["identity"]
            self.bindings.setdefault(identity, set()).add(device)
            self.devices[device] = identity
            # §13.3: flush the store-and-forward queues for the identity and the device, in order
            for key in (identity, device):
                for m in self.inbox.pop(key, []):
                    self.flush_to(device, m)
            # §12.7 rule 3: a device that binds while an attempt for its identity is live becomes a new leg
            for sid, a in self.attempts.items():
                if a.identity == identity and a.outcome is None and device not in a.legs:
                    inv = self.invites.get(sid)
                    # unexpired as the envelope pipeline means it: `expired` is expires_at < now (§12.9)
                    if inv is not None and inv.get("expires_at", self.now + 1) >= self.now:
                        a.legs[device] = "delivered"
                        self.emit({"deliver": {"leg": device, "type": "invite", "id": sid}})
        elif ev["relay"] == "unbind":
            self.bindings.get(ev["identity"], set()).discard(ev["device"])
        elif ev["relay"] == "leg_expired":
            a = self.attempts.get(ev["session"])  # an expiry for an attempt no longer held changes nothing
            if a is not None and a.legs.get(ev["leg"]) == "delivered":
                a.legs[ev["leg"]] = "expired"
                self.check_complete(a)
        else:
            raise ValueError(ev)

    def legs_for(self, to: str) -> list[str]:
        if to in self.devices:
            return [to] if to in self.bindings.get(self.devices[to], set()) else []
        return sorted(self.bindings.get(to, ()))

    def known(self, to: str) -> bool:
        """Impl (spec-gap 17): a recipient is known if any device has ever bound for it on this relay."""
        return to in self.bindings or to in self.devices

    def enqueue(self, m: dict) -> None:
        self.inbox.setdefault(m["to"], []).append(dict(m, _deadline=min(m.get("expires_at", self.now + self.retention), self.now + self.retention)))
        self.emit({"queue": {"to": m["to"], "type": m["type"]}})

    def flush_to(self, device: str, m: dict) -> None:
        if m["type"] == "invite":
            # A queued invite becomes a tracked leg on delivery (§12.7 rule 3)
            sid = m["id"]
            a = self.attempts.get(sid)
            if a is None:
                a = Attempt(sid, m["from"], m["to"])
                self.attempts[sid] = a
                self.invites[sid] = m
            a.legs[device] = "delivered"
            self.emit({"deliver": {"leg": device, "type": "invite", "id": sid}})
        else:
            self.emit({"deliver": {"leg": device, "type": m["type"], "id": m["id"]}})

    def expire_queues(self) -> None:
        for to in sorted(self.inbox):
            keep = []
            for m in self.inbox[to]:
                if m["_deadline"] <= self.now:
                    # §13.3: the relay holds envelopes only within the delivery boundary; the initiator's
                    # §12.9 timers are the backstop — nothing is signaled (Impl, spec-gap 17).
                    self.emit({"dequeue": {"to": to, "type": m["type"], "why": "expired"}})
                else:
                    keep.append(m)
            if keep:
                self.inbox[to] = keep
            else:
                del self.inbox[to]

    def recv(self, m: dict) -> None:
        if m["type"] == "introduction":
            # §19.4 anti-enumeration: an introduction to an unknown identity and one to an offline identity
            # get the identical treatment — queued, no error. (Impl, spec-gap 14: §13.2 "no silent drops"
            # yields to §19.4 here.) Bound devices receive it immediately.
            devices = self.legs_for(m["to"])
            if devices:
                for d in devices:
                    self.emit({"deliver": {"leg": d, "type": "introduction"}})
            else:
                self.enqueue(m)
            return
        if m["type"] == "invite":
            legs = self.legs_for(m["to"])
            if not legs:
                if self.known(m["to"]):
                    self.enqueue(m)  # §13.3 store-and-forward for a known, offline recipient
                else:
                    # Session traffic to an identity this relay has never seen is refused with a signed error (§13.2).
                    self.emit({"send": {"type": "error", "to": m["from"], "reason": "transport.unknown-recipient", "in_reply_to": m["id"]}})
                return
            self.invites[m["id"]] = m
            return self.relay_event({"relay": "invite", "session": m["id"], "from": m["from"], "to": m["to"], "legs": legs})
        a = self.attempts.get(m.get("session"))
        if a is None:
            if m["type"] == "cancel":
                # a cancel for an invite that is still queued: drop the queued invite (§12.11)
                queued = self.inbox.get(m["to"], [])
                remaining = [q for q in queued if not (q["type"] == "invite" and q["id"] == m["session"])]
                if len(remaining) != len(queued):
                    self.inbox[m["to"]] = remaining
                    if not remaining:
                        del self.inbox[m["to"]]
                    self.emit({"dequeue": {"to": m["to"], "type": "invite", "why": "cancelled"}})
                    return
            return self.route_plain(m)
        t = m["type"]
        if t not in ("progress", "answer", "reject", "cancel") or m.get("in_reply_to") is not None:
            # Post-answer and renegotiation traffic (update/info/bye, update replies) is not attempt-scoped:
            # plain routing by `to` (§13.2), queued for a known-offline device (§13.3).
            return self.route_plain(m)
        if t == "cancel" and m["from"] == a.initiator:
            # §12.7 rule 3: per-leg cancel to every leg that has not terminated — or, addressed to a device, to that
            # leg alone (§12.11: "a specific device DID (targeted cancel of one leg)")
            only = m.get("to") if m.get("to") in a.legs else None
            if only is None and m.get("to") not in (None, a.identity):
                return self.route_plain(m)  # addressed to a device that is no leg of this attempt: not the attempt's business
            for leg, st in a.legs.items():
                if st == "delivered" and only in (None, leg):
                    a.legs[leg] = "cancelled"
                    self.emit({"deliver": {"leg": leg, "type": "cancel", "reason": m["reason"]}})
            if a.outcome is None and "delivered" not in a.legs.values():
                a.outcome = "cancelled"
            return
        leg = m["from"]
        if a.legs.get(leg) is None:
            return self.route_plain(m)  # spec-gap 82: not a leg of this attempt — routed like any envelope, never dropped
        if t == "answer":
            # Never withheld, whatever the leg's state (spec-gap 86): only the initiator ends a leg that has
            # answered — bye already-answered / cancelled / failed (§12.7 rule 4, §12.5 rule 3, §12.4). The
            # record changes only for a leg that was still outstanding: a cancelled, expired or rejected leg
            # that answers stays recorded as such.
            if a.legs[leg] == "delivered":
                a.legs[leg] = "answered"
                if a.outcome is None:
                    a.outcome = "answered"
            self.emit({"forward": {"type": "answer", "from": leg}})
            return
        if a.legs[leg] in TERMINAL:
            # A stale progress or a second reject from a leg that is done would read, at an initiator that
            # cannot see legs, as the attempt's own; nobody needs it, so the relay screens it (spec-gap 86).
            self.emit({"drop": "leg-terminated"})
            return
        if t == "progress":
            self.emit({"forward": {"type": "progress", "status": m.get("status"), "from": leg}})
        elif t == "reject":
            a.legs[leg] = "rejected"
            a.reasons[leg] = m["reason"]
            self.check_complete(a)
        else:
            self.emit({"drop": "not-attempt-scoped"})

    def route_plain(self, m: dict) -> None:
        legs = self.legs_for(m.get("to", ""))
        if legs:
            for d in legs:
                self.emit({"deliver": {"leg": d, "type": m["type"], "id": m["id"]}})
        elif self.known(m.get("to", "")):
            self.enqueue(m)
        else:
            # spec-gap 82: §13.2 — a relay MUST NOT silently drop an envelope on a live connection. Traffic for a session
            # it holds no attempt for is routed like any envelope; with no route, the sender is told so.
            self.emit({"send": {"type": "error", "to": m["from"], "reason": "transport.unknown-recipient", "in_reply_to": m["id"]}})

    def check_complete(self, a: Attempt) -> None:
        """§12.7 rule 6: when the final outstanding leg terminates without an answer, forward the
        most informative reject as the attempt outcome."""
        if a.outcome is not None or any(st == "delivered" for st in a.legs.values()):
            return
        reasons = list(a.reasons.values())
        if not reasons:
            # spec-gap 76: no leg said anything — nothing to forward, and the relay may not invent a reject in a
            # leg's name (§15.2): it speaks for itself, in its own signed error
            a.outcome = "no-response"
            self.emit({"send": {"type": "error", "to": a.initiator, "session": a.session, "reason": "transport.no-response",
                                "in_reply_to": a.session}})
            return
        a.outcome = "rejected"
        best = next((r for r in REASON_RANK if r in reasons), reasons[0])
        src = next(leg for leg, r in a.reasons.items() if r == best)
        self.emit({"forward": {"type": "reject", "reason": best, "from": src}})

    def snapshot(self, ids) -> dict:
        return {i: self.attempts[i].snapshot() if i in self.attempts else None for i in ids}

    def inbox_snapshot(self) -> dict:
        return {k: len(v) for k, v in sorted(self.inbox.items()) if v}
