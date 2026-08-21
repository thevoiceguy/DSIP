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
        self.bindings: dict[str, set[str]] = {}        # identity → bound devices (§13.2)
        self.inbox: dict[str, list[dict]] = {}         # identity → queued introductions (§19.4 / §13.3)

    def emit(self, e: dict) -> None:
        self.out.append(e)

    def step(self, event: dict) -> list[dict]:
        self.out = []
        if "advance" in event:
            self.now += event["advance"]
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
            self.bindings.setdefault(ev["identity"], set()).add(ev["device"])
            # flush store-and-forward inbox for the identity (§13.3 boundary)
            for m in self.inbox.pop(ev["identity"], []):
                self.emit({"deliver": {"leg": ev["device"], "type": "introduction"}})
        elif ev["relay"] == "unbind":
            self.bindings.get(ev["identity"], set()).discard(ev["device"])
        elif ev["relay"] == "leg_expired":
            a = self.attempts[ev["session"]]
            if a.legs.get(ev["leg"]) == "delivered":
                a.legs[ev["leg"]] = "expired"
                a.reasons.setdefault(ev["leg"], "endpoint.unavailable")
                self.check_complete(a)
        else:
            raise ValueError(ev)

    def recv(self, m: dict) -> None:
        if m["type"] == "introduction":
            # §19.4 anti-enumeration: an introduction to an unknown identity and one to an offline identity
            # get the identical treatment — queued, no error. (Impl, spec-gap 14: §13.2 "no silent drops"
            # yields to §19.4 here.) Bound devices receive it immediately.
            devices = sorted(self.bindings.get(m["to"], ()))
            if devices:
                for d in devices:
                    self.emit({"deliver": {"leg": d, "type": "introduction"}})
            else:
                self.inbox.setdefault(m["to"], []).append(m)
                self.emit({"queue": {"to": m["to"], "type": "introduction"}})
            return
        if m["type"] == "invite":
            # Session traffic to an identity with no bound device is refused with a signed error (§13.2).
            if not self.bindings.get(m["to"]):
                self.emit({"send": {"type": "error", "to": m["from"], "reason": "transport.unknown-recipient", "in_reply_to": m["id"]}})
                return
            return self.relay_event({"relay": "invite", "session": m["id"], "from": m["from"], "to": m["to"],
                                     "legs": sorted(self.bindings[m["to"]])})
        a = self.attempts.get(m.get("session"))
        if a is None:
            self.emit({"drop": "unknown-attempt"})
            return
        t = m["type"]
        if t == "cancel" and m["from"] == a.initiator:
            # §12.7 rule 3: per-leg cancel to every leg that has not terminated
            for leg, st in a.legs.items():
                if st == "delivered":
                    a.legs[leg] = "cancelled"
                    self.emit({"deliver": {"leg": leg, "type": "cancel", "reason": m["reason"]}})
            if a.outcome is None:
                a.outcome = "cancelled"
            return
        leg = m["from"]
        if a.legs.get(leg) is None:
            self.emit({"drop": "unknown-leg"})
            return
        if a.legs[leg] in TERMINAL and not (t == "answer" and a.legs[leg] == "answered"):
            self.emit({"drop": "leg-terminated"})
            return
        if t == "progress":
            self.emit({"forward": {"type": "progress", "status": m.get("status"), "from": leg}})
        elif t == "answer":
            a.legs[leg] = "answered"
            if a.outcome is None:
                a.outcome = "answered"
            # Always forwarded: the initiator decides (first-accept, late → bye already-answered).
            self.emit({"forward": {"type": "answer", "from": leg}})
        elif t == "reject":
            a.legs[leg] = "rejected"
            a.reasons[leg] = m["reason"]
            self.check_complete(a)
        else:
            self.emit({"drop": "not-attempt-scoped"})

    def check_complete(self, a: Attempt) -> None:
        """§12.7 rule 6: when the final outstanding leg terminates without an answer, forward the
        most informative reject as the attempt outcome."""
        if a.outcome is not None or any(st == "delivered" for st in a.legs.values()):
            return
        a.outcome = "rejected"
        reasons = list(a.reasons.values())
        best = None
        for r in REASON_RANK:
            if r in reasons:
                best = r
                break
        if best is None:
            best = reasons[0] if reasons else "endpoint.unavailable"
        src = next(leg for leg, r in a.reasons.items() if r == best)
        self.emit({"forward": {"type": "reject", "reason": best, "from": src}})

    def snapshot(self, ids) -> dict:
        return {i: self.attempts[i].snapshot() if i in self.attempts else None for i in ids}

    def inbox_snapshot(self) -> dict:
        return {k: len(v) for k, v in sorted(self.inbox.items()) if v}
