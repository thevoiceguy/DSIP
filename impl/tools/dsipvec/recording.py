"""Recording Profile (draft, `recording/0.1`) — reference for the `recording/` vectors.

Spec: C§4 (a counterparty's consent: render, hold until acceptance, decline with policy.recording-declined),
C§5 (a recorded conversation; a recorder is receive-only), C§6 (the recorder leg's checks). Contract:
impl/vectors/README.md, kind `recording`.

Impl (spec-gap 107): an unregistered recording state is read as `on`; acceptance is per session and per recorder.
"""
from __future__ import annotations

DECLINED = "policy.recording-declined"


class Consent:
    """One counterparty's client in one call (C§4)."""

    def __init__(self, ctx: dict):
        self.role = ctx["role"]
        self.policy = ctx.get("accept", "ask")
        self.disclosure = None
        self.pending = False
        self.accepted: set[str] = set()
        self.answered = False
        self.ended = None

    def _decline(self) -> list:
        t = "reject" if self.role == "callee" and not self.answered else "bye"
        self.ended, self.pending = DECLINED, False
        return [{"send": {"type": t, "reason": DECLINED}}]

    def step(self, ev: dict) -> list:
        if "received" in ev:
            if self.ended:
                return []
            r = ev["received"]
            if r["type"] == "answer":
                self.answered = True
            rec = r.get("recording") or {"state": "off"}
            if rec["state"] == "off":
                if self.disclosure is None:
                    return []
                out = [{"render": {"state": "off", "recorder": self.disclosure["recorder"]}}]
                self.disclosure, self.pending = None, False
                return out
            decl = {"state": rec["state"], "recorder": rec["recorder"]}
            if "purpose" in rec:
                decl["purpose"] = rec["purpose"]
            out = []
            if decl != self.disclosure:
                out.append({"render": dict(decl)})
                self.disclosure = decl
            if rec["state"] == "paused" or decl["recorder"] in self.accepted:
                self.pending = False
            else:
                if self.policy == "always":
                    self.accepted.add(decl["recorder"])
                    out.append({"accepted": {"recorder": decl["recorder"], "by": "policy"}})
                elif self.policy == "never":
                    out += self._decline()
                else:
                    self.pending = True
            return out
        loc = ev.get("local")
        if loc == "accept":
            if not self.pending:
                return []
            self.accepted.add(self.disclosure["recorder"])
            self.pending = False
            return [{"accepted": {"recorder": self.disclosure["recorder"], "by": "user"}}]
        if loc == "decline":
            return self._decline() if not self.ended and self.disclosure is not None else []
        if loc == "answer":
            if self.ended or self.role != "callee":
                return []
            if self.pending:
                return [{"blocked": "awaiting-acceptance"}]
            self.answered = True
            return [{"send": {"type": "answer"}}]
        raise ValueError(ev)

    def snapshot(self) -> dict:
        return {"disclosure": self.disclosure, "pending": self.pending, "hold_media": self.pending and not self.ended,
                "accepted": sorted(self.accepted), "ended": self.ended}


def conversation(i: dict) -> dict:
    """C§5: is the conversation recorded, may this member send, is a sender's content rendered."""
    rec = sorted(({"device": x["device"], "subject": x["subject"]} for x in i["leaves"] if "dsip.record" in x["capabilities"]),
                 key=lambda x: x["device"])
    acc = set(i.get("accepted", []))
    out = {"recorded": bool(rec), "recorders": rec, "may_send": all(x["device"] in acc for x in rec)}
    if "sender" in i:
        leaf = next((x for x in i["leaves"] if x["device"] == i["sender"]), None)
        out["render_sender"] = leaf is not None and "dsip.record" not in leaf["capabilities"]
    return out


def recording_session(i: dict) -> dict:
    """C§6: the recording party's checks before it streams to its recorder."""
    d, r, o = i["declared"], i["recorder"], i["offer"]
    if d.get("state", "off") == "off":
        return {"refused": "not-declared"}
    if r["identity"] != d.get("recorder"):
        return {"refused": "recorder-mismatch"}
    if "dsip.record" not in r["capabilities"]:
        return {"refused": "missing-capability"}
    rs = o["recording_session"]
    if rs["of"] != d["session"]:
        return {"refused": "wrong-session"}
    who = {p["identity"] for p in rs["participants"]}
    seen = set()
    if not rs.get("streams"):
        return {"refused": "bad-stream-map"}
    for s in rs["streams"]:
        m = s["media"]
        if not isinstance(m, int) or isinstance(m, bool) or not 0 <= m < len(o["media"]) or m in seen \
                or s["participant"] not in who:
            return {"refused": "bad-stream-map"}
        seen.add(m)
    if any(o["media"][s["media"]].get("direction") != "sendonly" for s in rs["streams"]):
        return {"refused": "direction"}
    return {"ok": True}


def run(v: dict):
    i = v["input"]
    if i.get("check") == "conversation":
        return conversation(i)
    if i.get("check") == "recording-session":
        return recording_session(i)
    m = Consent(v["context"])
    return [{"emit": m.step(st["event"]), **m.snapshot()} for st in i["steps"]]
