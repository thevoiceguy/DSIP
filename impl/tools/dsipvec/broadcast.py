"""§22 Verified Broadcast + §9.3 subscription protocol — Python reference for the broadcast vectors.

Components:
- `Authority`: the target's relay/domain endpoint. Holds signed publication records, answers
  `subscribe` with policy (public / allowlist / capability token; anti-enumeration), emits
  seq-ordered `notify`s, terminates lapsed subscriptions, attaches provenance statements.
- `Subscriber`: tracks its subscriptions, enforces seq ordering and terminal state.
- `evaluate_publication` / `evaluate_provenance` / `select_variant`: the receiver's stateless checks.

Every `Impl:` comment marks a choice the spec leaves open (impl/docs/spec-gaps.md 18–21).
"""
from __future__ import annotations

from .registry import SUBSCRIPTION_EVENTS, resolve_reason

INTEGRITY_MODES = ("metadata-only", "derivative-bound")           # §22.2 core; others reserved
PROVENANCE_OPERATIONS = ("transcode", "relay", "repackage")        # dsip-provenance-operation (§22.3, v0.7)


def stream_in_namespace(stream_id: str, publisher: str) -> bool:
    """Impl (spec-gap 18): a stream_id is the publisher DID or a colon-suffixed extension of it."""
    return stream_id == publisher or stream_id.startswith(publisher + ":")


# ---------------------------------------------------------------- authority

class Authority:
    """Spec: §9.3 (subscribe/notify, authorization, anti-enumeration), §22.1 (publication records),
    §22.3 (provenance statements carried with the record)."""

    def __init__(self, ctx: dict):
        self.now = ctx.get("start", 0)
        self.identities: dict[str, str] = dict(ctx.get("identities", {}))
        self.publications: dict[str, dict] = {}      # stream_id → {"publication", "publisher", "state", "expires_at", "variants", "policy"}
        self.provenance: dict[str, list[dict]] = {}  # stream_id → provenance statements (abbrev)
        self.subscriptions: dict[str, dict] = {}     # subscription id → {...}
        self.policy: dict[str, dict] = {}            # target → {"mode": "public"|"allow", "allow": [...]}
        self.capabilities: dict[str, str] = {}       # token → target
        self.bound: set[str] = set()                 # bound identities (presence)
        self.out: list[dict] = []

    def identity_of(self, did: str) -> str:
        return self.identities.get(did, did)

    def emit(self, e: dict) -> None:
        self.out.append(e)

    def send(self, **f) -> None:
        self.emit({"send": {k: v for k, v in f.items() if v is not None}})

    def step(self, event: dict) -> list[dict]:
        self.out = []
        if "advance" in event:
            self.now += event["advance"]
            self.expire()
        elif "recv" in event:
            self.recv(event["recv"])
        elif "local" in event:
            self.local(event)
        elif "relay" in event:
            if event["relay"] == "bind":
                self.bound.add(event["identity"])
                self.presence_changed(event["identity"])
            elif event["relay"] == "unbind":
                self.bound.discard(event["identity"])
                self.presence_changed(event["identity"])
        else:
            raise ValueError(event)
        return self.out

    # ------------------------------------------------------------ local policy

    def local(self, ev: dict) -> None:
        if ev["local"] == "policy":
            self.policy[ev["target"]] = {"mode": ev["mode"], "allow": list(ev.get("allow", []))}
        elif ev["local"] == "issue_capability":
            self.capabilities[ev["token"]] = ev["target"]
        else:
            raise ValueError(ev)

    # ------------------------------------------------------------ records

    def recv(self, m: dict) -> None:
        t = m["type"]
        identity = self.identity_of(m["from"])
        if t == "publish":
            # §22.1: a publication record is signed by the publisher (or a delegate); the record's `publisher`
            # MUST be the verified identity (Impl, spec-gap 18), and stream_id lives under it.
            if m["publisher"] != identity:
                return self.emit({"drop": "publisher-mismatch"})
            if not stream_in_namespace(m["stream_id"], m["publisher"]):
                return self.emit({"drop": "stream-id-namespace"})
            cur = self.publications.get(m["stream_id"])
            if cur is not None and m["id"] <= cur["publication"]:
                # §8.3 spirit: newer replaces older; ULIDs order publications of one stream (Impl)
                return self.emit({"drop": "stale-publication"})
            self.publications[m["stream_id"]] = {"publication": m["id"], "publisher": m["publisher"], "state": m["state"],
                                                 "expires_at": m["expires_at"], "variants": list(m.get("variants", [])),
                                                 "policy": dict(m.get("policy", {}))}
            # Statements reference a specific publication id (§22.3); a replacing record starts with none.
            self.provenance.pop(m["stream_id"], None)
            self.emit({"publication": {"stream": m["stream_id"], "state": m["state"]}})
            self.notify_all("publication", m["stream_id"])
        elif t == "unpublish":
            cur = self.publications.get(m["stream_id"])
            if cur is None or cur["publication"] != m["publication"]:
                return self.emit({"drop": "unknown-publication"})
            if cur["publisher"] != identity:
                return self.emit({"drop": "publisher-mismatch"})
            cur["state"] = "withdrawn"
            self.emit({"publication": {"stream": m["stream_id"], "state": "withdrawn"}})
            self.notify_all("publication", m["stream_id"])
        elif t == "provenance":
            # §22.3: a processor adds its own signed statement; it never overwrites the publisher's record.
            cur = self.publications.get(m["original_stream"])
            if cur is None or cur["publication"] != m["original_publication"]:
                return self.emit({"drop": "provenance-unknown-publication"})
            if m["processor"] != identity:
                return self.emit({"drop": "provenance-processor-mismatch"})
            if m["input_variant"] not in [v["id"] for v in cur["variants"]]:
                return self.emit({"drop": "provenance-variant-unknown"})
            self.provenance.setdefault(m["original_stream"], []).append(
                {"processor": m["processor"], "operation": m["operation"], "input_variant": m["input_variant"],
                 "output_variant": m["output_variant"]})
            self.emit({"provenance": {"stream": m["original_stream"], "processor": m["processor"]}})
            self.notify_all("publication", m["original_stream"])
        elif t == "subscribe":
            self.recv_subscribe(m, identity)
        else:
            self.emit({"drop": "not-broadcast"})

    # ------------------------------------------------------------ subscriptions (§9.3)

    def authorized(self, target: str, identity: str, token: str | None) -> bool:
        if token is not None and self.capabilities.get(token) == target:
            return True
        pol = self.policy.get(target, {"mode": "public", "allow": []})
        return pol["mode"] == "public" or identity in pol["allow"]

    def target_exists(self, target: str, events: list) -> bool:
        if "publication" in events:
            return target in self.publications
        return target in self.identities.values() or target in self.bound or any(t == target for t in self.policy)

    def recv_subscribe(self, m: dict, identity: str) -> None:
        target, events = m["target"], list(m["events"])
        existing = next((sid for sid, s in self.subscriptions.items()
                         if s["subscriber"] == identity and s["target"] == target and s["events"] == events), None)
        if m["expires_in"] == 0:
            # §9.3: expires_in 0 terminates a matching subscription (no notify is owed to the requester)
            if existing is not None:
                del self.subscriptions[existing]
                self.emit({"subscription": {"id": existing, "state": "terminated"}})
            else:
                self.emit({"drop": "no-matching-subscription"})
            return
        # §9.3 anti-enumeration: unauthorized and nonexistent targets get the identical reject
        if not self.target_exists(target, events) or not self.authorized(target, identity, m.get("capability")):
            self.send(type="reject", to=m["from"], session=m["id"], reason="policy.blocked")
            return
        cap = min(SUBSCRIPTION_EVENTS.get(e, 86400) for e in events)
        lifetime = min(m["expires_in"], cap)
        if existing is not None:
            # renewal replaces the prior subscription (same target+events)
            del self.subscriptions[existing]
            self.emit({"subscription": {"id": existing, "state": "replaced"}})
        sub = {"subscriber": identity, "device": m["from"], "target": target, "events": events,
               "expires_at": self.now + lifetime, "seq": 0}
        self.subscriptions[m["id"]] = sub
        # Acceptance is signaled by the first notify, which carries the current state
        self.notify(m["id"], "active")

    def body_for(self, sub: dict) -> dict:
        if "publication" in sub["events"]:
            pub = self.publications.get(sub["target"])
            body = {"event": "publication", "state": pub["state"] if pub else "unknown"}
            if pub:
                body["publication"] = pub["publication"]
                prov = self.provenance.get(sub["target"], [])
                if prov:
                    body["provenance"] = [p["processor"] for p in prov]
            return body
        return {"event": "presence", "state": "available" if sub["target"] in self.bound else "offline"}

    def notify(self, sid: str, state: str, reason: str | None = None) -> None:
        sub = self.subscriptions[sid]
        sub["seq"] += 1
        self.send(type="notify", to=sub["device"], subscription=sid, seq=sub["seq"], state=state, reason=reason,
                  body=self.body_for(sub))
        if state == "terminated":
            del self.subscriptions[sid]

    def notify_all(self, event: str, target: str) -> None:
        for sid in sorted(s for s, sub in self.subscriptions.items() if sub["target"] == target and event in sub["events"]):
            self.notify(sid, "active")

    def presence_changed(self, identity: str) -> None:
        self.notify_all("presence", identity)

    def expire(self) -> None:
        for sid in sorted(self.subscriptions):
            if self.subscriptions[sid]["expires_at"] <= self.now:
                # §9.3: soft state — lapsed subscriptions end with a terminal notify carrying session.expired
                self.notify(sid, "terminated", "session.expired")
        for stream, pub in list(self.publications.items()):
            if pub["state"] in ("live", "scheduled") and pub["expires_at"] <= self.now:
                pub["state"] = "expired"
                self.emit({"publication": {"stream": stream, "state": "expired"}})
                self.notify_all("publication", stream)

    def snapshot_publications(self) -> dict:
        return {s: {"publication": p["publication"], "publisher": p["publisher"], "state": p["state"]}
                for s, p in sorted(self.publications.items())}

    def snapshot_subscriptions(self) -> dict:
        return {sid: {"subscriber": s["subscriber"], "target": s["target"], "events": s["events"], "seq": s["seq"],
                      "expires_at": s["expires_at"]} for sid, s in sorted(self.subscriptions.items())}


# ---------------------------------------------------------------- subscriber

class Subscriber:
    """Spec: §9.3 — seq ordering (discard lower-than-seen), terminal state, renewal as a fresh subscribe."""

    def __init__(self, ctx: dict):
        self.now = ctx.get("start", 0)
        self.subs: dict[str, dict] = {}
        self.out: list[dict] = []

    def emit(self, e: dict) -> None:
        self.out.append(e)

    def step(self, event: dict) -> list[dict]:
        self.out = []
        if "advance" in event:
            self.now += event["advance"]
            for sid, s in sorted(self.subs.items()):
                if s["state"] == "active" and s["expires_at"] <= self.now:
                    s["state"] = "lapsed"
                    self.emit({"ui": "subscription_lapsed", "subscription": sid})
        elif "local" in event and event["local"] == "subscribe":
            ev = event
            self.subs[ev["id"]] = {"target": ev["target"], "events": list(ev["events"]), "state": "pending", "seq": 0,
                                   "expires_at": self.now + ev["expires_in"]}
            self.emit({"send": {"type": "subscribe", "to": ev["to"], "id": ev["id"], "target": ev["target"],
                                "events": list(ev["events"]), "expires_in": ev["expires_in"]}})
        elif "recv" in event:
            self.recv(event["recv"])
        else:
            raise ValueError(event)
        return self.out

    def recv(self, m: dict) -> None:
        if m["type"] == "reject":
            s = self.subs.get(m.get("session"))
            if s is None:
                return self.emit({"drop": "unknown-subscription"})
            s["state"] = "rejected"
            self.emit({"ui": "subscription_rejected", "reason": resolve_reason(m["reason"], "reject").effective})
            return
        if m["type"] != "notify":
            return self.emit({"drop": "not-subscription"})
        s = self.subs.get(m["subscription"])
        if s is None:
            return self.emit({"drop": "unknown-subscription"})
        if s["state"] in ("terminated", "rejected"):
            return self.emit({"drop": "terminated-subscription"})
        if m["seq"] <= s["seq"]:
            return self.emit({"drop": "stale-seq"})  # §9.3: receivers discard lower-than-seen seq
        s["seq"] = m["seq"]
        if m["state"] == "terminated":
            s["state"] = "terminated"
            self.emit({"ui": "subscription_terminated", "reason": m.get("reason")})
            return
        s["state"] = "active"
        body = m.get("body", {})
        self.emit({"ui": "notify", "event": body.get("event"), "state": body.get("state")})

    def snapshot(self) -> dict:
        return {sid: {"target": s["target"], "state": s["state"], "seq": s["seq"]} for sid, s in sorted(self.subs.items())}


# ---------------------------------------------------------------- receiver (stateless)

def select_variant(variants: list, caps: dict) -> str | None:
    """Receiver picks the first advertised variant whose codec and transport it supports (§22.1 order = publisher preference)."""
    for v in variants:
        if v.get("codec") in caps.get("codecs", []) and v.get("transport") in caps.get("transports", []):
            return v["id"]
    return None


def evaluate_provenance(stmt: dict, stmt_identity: str, publication: dict) -> dict:
    """§22.3 checks for one statement against the verified publication it references."""
    if stmt.get("original_publication") != publication["id"]:
        return {"verdict": "reject", "code": "provenance-unknown-publication"}
    if stmt.get("original_stream") != publication["stream_id"]:
        return {"verdict": "reject", "code": "provenance-stream-mismatch"}
    if stmt.get("processor") != stmt_identity:
        return {"verdict": "reject", "code": "provenance-processor-mismatch"}
    if stmt.get("input_variant") not in [v["id"] for v in publication.get("variants", [])]:
        return {"verdict": "reject", "code": "provenance-variant-unknown"}
    out = {"verdict": "accept", "processor": stmt["processor"], "operation": stmt["operation"],
           "integrity_mode": "derivative-bound"}
    pol = publication.get("policy", {})
    if stmt["operation"] == "transcode" and pol.get("transcoding") in ("forbidden", "denied"):
        out["policy_violation"] = "transcoding"  # §16.4: policy is displayed/enforced by receivers, not magic
    if pol.get("redistribution") == "forbidden":
        out["policy_violation"] = "redistribution"
    return out
