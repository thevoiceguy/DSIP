"""Messaging Profile 1.0 reference semantics (v0.8 draft, cited M§n).

Spec: `v0.8/dsip-messaging-profile-v0.8-draft.md`. Written before any Rust implementation; the
`messaging/` vectors pin this module's choices and `dsip-messaging` mirrors it.

Checks (`input.check`):
- `payload`  JSON Schema shape of a profile message or object (M§5, M§8).
- `message`  schema + stateless semantic rules for a profile message payload (M§5).
- `object`   schema + stateless rules for a decrypted content object (M§8, M§10, M§11, M§12).
- `hub-trace`, `mailbox-trace`  scripted state traces of the hub (M§6.5–M§6.8, M§7.3, M§9.3,
  M§11.2) and the mailbox (M§4.4, M§5.4–M§5.7, M§6.6, M§12.2, M§14.2).
- `resume-trace`  what a device holds durably across a restart: ack cursor and seq positions (M§5.4,
  M§8.5, spec-gap 44).

MLS itself is abstracted: traces carry what a hub or mailbox can observe (epoch, commit adds and
removes, validity, digests), exactly as relay traces abstract signatures.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from jsonschema import Draft202012Validator

from . import ulid as U

REPO_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_DIR = REPO_ROOT / "v0.8" / "dsip-messaging-schemas-draft" / "schemas"

MAX_MLS_BYTES = 24576          # M§5.1
MAX_LIFETIME_S = 60            # M§5.1: delivery envelopes, not records
EPHEMERAL_LIFETIME_S = 10      # M§11.2
ULID_TOLERANCE_S = 300         # M§8.1 (§20.6 applied to content)
REACTION_MAX_BYTES = 32        # M§8.2
KEY_PACKAGES_PER_DEVICE = 100  # M§5.5 RECOMMENDED bound
ORIGIN_SKEW_S = 300            # M§14.2: origin issued_at within 300 s of the hub deposit

MESSAGE_SCHEMAS = ["deposit", "accepted", "sync", "items", "key-packages", "key-package-fetch", "blob-put",
                   "mailbox-config"]
OBJECT_SCHEMAS = ["content", "receipt", "activity", "archive-key", "call-event", "archive-record"]
MESSAGING_PROFILE = "messaging/1.0"

# Registries (M§17). Membership is checked here; the schemas only check token shape.
DEPOSIT_CLASSES = {"handshake", "application", "welcome", "group-info", "ephemeral", "archive", "introduction", "grant"}
FIRST_CONTACT_CLASSES = ("introduction", "grant")  # M§14.1 (spec-gap 54): carry a signed core envelope, no group
CONTENT_KINDS = {"text", "audio", "video", "image", "file", "contact", "location"}
CONTENT_PURPOSES = {"message", "voice-message", "video-message", "voicemail", "attachment", "reaction",
                    "callback-request"}
RECEIPT_KINDS = {"delivered", "read", "played"}
ACTIVITIES = {"typing", "recording-audio", "recording-video", "uploading"}
MAILBOX_MODES = {"sync", "queue"}
CONVERSATION_KINDS = {"personal", "direct", "group"}
MESSAGE_GRANT_SCOPES = {"dsip.message", "dsip.invite"}  # M§14.2 condition 2

# M§5.2 class table: required and permitted class-specific fields.
_DEPOSIT_BASE = {"dsip", "type", "id", "from", "to", "issued_at", "expires_at", "group", "class", "recipient"}
DEPOSIT_REQUIRED = {
    "handshake": {"mls"},
    "application": {"mls"},
    "welcome": {"mls", "hub"},
    "group-info": {"mls"},
    "ephemeral": {"sealed"},
    "archive": {"archive", "akid", "ref_group", "ref_seq"},
    "introduction": {"envelope"},
    "grant": {"envelope"},
}
DEPOSIT_ALLOWED = {
    "handshake": {"mls", "seq", "welcome", "group_info", "ratchet_tree_blob", "grants"},
    "application": {"mls", "seq", "blobs"},
    "welcome": {"mls", "hub", "grants", "origin", "successor_of", "ratchet_tree_blob"},
    "group-info": {"mls", "ratchet_tree_blob"},
    "ephemeral": {"sealed"},
    "archive": {"archive", "akid", "ref_group", "ref_seq"},
    "introduction": {"envelope"},
    "grant": {"envelope"},
}
INTRODUCTION_MAX_BYTES = 4096   # §19.4
SIZED_FIELDS = ("mls", "welcome", "group_info", "sealed", "archive")


def accept(**extra) -> dict:
    out = {"verdict": "accept"}
    out.update(extra)
    return out


def reject(code: str, reason: str | None = None) -> dict:
    out = {"verdict": "reject", "code": code}
    if reason:
        out["reason"] = reason
    return out


@lru_cache(maxsize=None)
def validator(name: str) -> Draft202012Validator:
    return Draft202012Validator(json.loads((SCHEMA_DIR / f"{name}.schema.json").read_text()))


def has_float(v) -> bool:
    if isinstance(v, bool):
        return False
    if isinstance(v, float):
        return True
    if isinstance(v, dict):
        return any(has_float(x) for x in v.values())
    if isinstance(v, list):
        return any(has_float(x) for x in v)
    return False


def decoded_len(b64: str) -> int:
    """Decoded length of unpadded base64url, from its length alone (alphabet is a schema check)."""
    return len(b64) * 3 // 4


def schema_ok(name: str, value) -> bool:
    return not any(True for _ in validator(name).iter_errors(value))


# ---------------------------------------------------------------- messages (M§5)

def check_message(p: dict) -> dict:
    t = p.get("type") if isinstance(p, dict) else None
    if t not in MESSAGE_SCHEMAS:
        return reject("unknown-type")
    if not schema_ok(t, p):
        return reject("schema-invalid")
    if p["expires_at"] - p["issued_at"] > MAX_LIFETIME_S:  # M§5.1
        return reject("lifetime-exceeded")
    if t == "deposit":
        return check_deposit(p)
    if t == "mailbox-config" and "mode" in p and p["mode"] not in MAILBOX_MODES:  # M§4.4, M§16
        return reject("mailbox-mode-unsupported", "mailbox.unsupported-mode")
    if t == "key-packages" and not p.get("key_packages") and "last_resort" not in p:  # M§5.5
        return reject("key-packages-empty")
    return accept()


def check_deposit(p: dict) -> dict:
    cls = p["class"]
    if cls not in DEPOSIT_CLASSES:  # M§5.2: class is structural, unknown is refused
        return reject("deposit-class-unsupported", "mailbox.unsupported-class")
    if cls == "ephemeral" and p["expires_at"] - p["issued_at"] > EPHEMERAL_LIFETIME_S:  # M§11.2
        return reject("lifetime-exceeded")
    present = set(p) - _DEPOSIT_BASE
    if not DEPOSIT_REQUIRED[cls] <= set(p) or not present <= DEPOSIT_ALLOWED[cls]:
        return reject("deposit-fields")
    if (cls in FIRST_CONTACT_CLASSES) != ("group" not in p) or (cls in FIRST_CONTACT_CLASSES and "recipient" not in p):
        return reject("deposit-fields")  # spec-gap 54: first-contact deposits name a recipient and no group
    if cls == "introduction" and len(p["envelope"]) > INTRODUCTION_MAX_BYTES:  # §19.4 on the compact envelope
        return reject("introduction-too-large", "transport.envelope-too-large")
    for f in SIZED_FIELDS:  # M§5.1
        if f in p and decoded_len(p[f]) > MAX_MLS_BYTES:
            return reject("object-too-large", "mailbox.object-too-large")
    return accept()


# ---------------------------------------------------------------- objects (M§8, M§10–M§13)

def check_object(o: dict, ctx: dict) -> dict:
    if has_float(o):  # §10.3 applies to MLS plaintext too (M§8.1)
        return reject("payload-float")
    name = o.get("object") if isinstance(o, dict) else None
    if name not in OBJECT_SCHEMAS:
        return accept(effective={"render": "ignore"})  # M§8.1: unknown object ignored
    if not schema_ok(name, o):
        return reject("schema-invalid")
    if name in ("content", "receipt", "activity"):
        if o["sender"] != ctx.get("leaf_identity"):  # M§8.1: sender = MLS leaf identity
            return reject("sender-mismatch")
        # spec-gap 52: an undisclosed read watermark travels in the personal group (M§10.5) and names the
        # conversation it describes, not the personal group's own
        private_read = name == "receipt" and o.get("kind") == "read" and ctx.get("conversation_kind") == "personal"
        if o["conversation"] != ctx.get("conversation") and not private_read:
            return reject("conversation-mismatch")
    if name in ("content", "receipt"):
        if abs(U.timestamp_ms(o["id"]) // 1000 - o["sent_at"]) > ULID_TOLERANCE_S:
            return reject("ulid-sent-at-mismatch")
    if name in ("archive-key", "call-event") and ctx.get("conversation_kind") != "personal":  # M§12.1, M§13.3
        return reject("personal-group-only")
    if name == "content":
        return check_content(o)
    if name == "receipt":
        if o["kind"] not in RECEIPT_KINDS:
            return accept(effective={"render": "ignore"})
        if o["kind"] == "read":
            ok = "through" in o and "targets" not in o
        else:
            ok = "targets" in o and "through" not in o
        return accept(effective={"receipt": o["kind"]}) if ok else reject("receipt-shape")
    if name == "activity":
        return accept(effective={"activity": o["activity"] if o["activity"] in ACTIVITIES else "active"})
    return accept()


_KIND_BODY = {
    "text": ("text",),
    "audio": ("blob", "duration_ms"),
    "video": ("blob", "duration_ms"),
    "image": ("blob",),
    "file": ("blob", "name"),
    "contact": ("did",),
    "location": ("lat_e7", "lon_e7"),
}


def check_content(o: dict) -> dict:
    kind, purpose = o["kind"], o["purpose"]
    if kind in CONTENT_KINDS:
        if not all(f in o for f in _KIND_BODY[kind]):
            return reject("content-body")
        eff_kind = kind
    else:  # M§8.2 fallback
        eff_kind = "file" if "blob" in o else "unsupported"
    if purpose == "reaction":
        if kind != "text" or not o.get("reply_to") or len(o.get("text", "").encode("utf-8")) > REACTION_MAX_BYTES:
            return reject("reaction-invalid")
    if purpose == "voicemail" and (kind not in ("audio", "video") or "session" not in o):  # M§13.2
        return reject("content-body")
    eff_purpose = purpose if purpose in CONTENT_PURPOSES else "message"
    return accept(effective={"kind": eff_kind, "purpose": eff_purpose})


def check_conversation_ext(ext: dict) -> dict:
    if not schema_ok("dsip-conversation", ext):
        return reject("schema-invalid")
    return accept(effective={"kind": ext["kind"] if ext["kind"] in CONVERSATION_KINDS else "group"})


# ---------------------------------------------------------------- hub (M§6.5–M§6.8, M§7.3)

class Hub:
    def __init__(self, ctx: dict):
        self.now = ctx["now"]
        self.kind = ctx.get("kind", "direct")
        self.owner = ctx.get("owner")
        self.epoch = ctx["epoch"]
        self.next_seq = ctx.get("next_seq", 1)
        self.roster = {i: set(d) for i, d in ctx["roster"].items()}
        self.digests: dict[str, int] = {}
        self.seq_class: dict[int, str] = {}
        self.pending: dict[str, list[int]] = {}
        self.group_info = False

    def step(self, ev: dict) -> list:
        if "advance" in ev:
            self.now += ev["advance"]
            return []
        if "ack" in ev:
            return self._ack(ev["ack"]["identity"], ev["ack"]["seq"])
        return self._deposit(ev["deposit"])

    @staticmethod
    def _error(d, reason):
        return [{"error": {"to": d["device"], "in_reply_to": d["id"], "reason": reason}}]

    def _deposit(self, d: dict) -> list:
        cls, ident = d["class"], d["identity"]
        if cls not in ("handshake", "application", "ephemeral", "group-info"):
            return self._error(d, "mailbox.unsupported-class")
        if cls == "group-info":
            # M§6.5 rule 6 / M§6.8: the hub keeps the latest GroupInfo so a returning device can
            # external-join, and forwards it to the members' mailboxes. Never sequenced.
            if ident not in self.roster:
                return self._error(d, "policy.blocked")
            self.group_info = True
            return [{"accepted": {"to": d["device"], "in_reply_to": d["id"]}}] + [
                {"fanout": {"to": i, "class": "group-info"}} for i in sorted(self.roster)
            ]
        if cls == "ephemeral":  # M§11.2: never sequenced or stored; dropped once expired
            if d["expires_at"] < self.now:
                return []
            if ident not in self.roster:
                return self._error(d, "policy.blocked")
            return [{"forward": {"to": i, "class": "ephemeral"}} for i in sorted(self.roster) if i != ident]
        if d["digest"] in self.digests:  # M§9.3
            return [{"accepted": {"to": d["device"], "in_reply_to": d["id"], "seq": self.digests[d["digest"]],
                                  "duplicate": True}}]
        commit = d.get("commit")
        external = bool(commit and commit.get("external"))
        if external:  # M§6.8
            if not (ident in self.roster or (self.kind == "personal" and ident == self.owner)):
                return self._error(d, "policy.blocked")
        elif ident not in self.roster:  # M§6.5 rule 1
            return self._error(d, "policy.blocked")
        e = d["epoch"]
        if cls == "application":
            if e not in (self.epoch, self.epoch - 1):  # M§6.5 rule 3
                return self._error(d, "mailbox.stale-epoch")
            return self._sequence(d, sorted(self.roster))
        # handshake
        if e != self.epoch:  # M§6.5 rule 2
            return self._error(d, "mailbox.commit-conflict" if (commit and e == self.epoch - 1) else "mailbox.stale-epoch")
        if not commit:  # standalone proposal: sequenced, no epoch change
            return self._sequence(d, sorted(self.roster))
        if not commit.get("valid", True):
            return self._error(d, "policy.blocked")
        for a in commit.get("adds", []):  # M§7.3: another member identity's devices are its own business
            if a["identity"] in self.roster and a["identity"] != ident:
                return self._error(d, "policy.blocked")
        by_ident: dict[str, list] = {}
        for r in commit.get("removes", []):
            by_ident.setdefault(r["identity"], []).append(r)
        for x, rs in by_ident.items():
            if x == ident:
                continue
            whole = {r["device"] for r in rs} >= self.roster.get(x, set())
            lapsed = all(r.get("delegation_valid", True) is False for r in rs)
            if not (whole or lapsed):
                return self._error(d, "policy.blocked")
        targets = sorted(self.roster)
        out = self._sequence(d, targets)
        before = {i: set(devs) for i, devs in self.roster.items()}
        for r in commit.get("removes", []):
            devs = self.roster.get(r["identity"])
            if devs is not None:
                devs.discard(r["device"])
                if not devs:
                    del self.roster[r["identity"]]
        for a in commit.get("adds", []):
            self.roster.setdefault(a["identity"], set()).add(a["device"])
        self.epoch += 1
        if not external:  # an external joiner joined by its own commit; welcomes go only to identities others added
            # spec-gap 50: to every identity that gained a device, including a member adding its own new device
            gained = {a["identity"] for a in commit.get("adds", []) if a["device"] not in before.get(a["identity"], set())}
            out += [{"fanout": {"to": i, "class": "welcome"}} for i in sorted(gained)]
        return out

    def _sequence(self, d: dict, targets: list) -> list:
        seq = self.next_seq
        self.next_seq += 1
        self.digests[d["digest"]] = seq
        self.seq_class[seq] = d["class"]
        out = [{"accepted": {"to": d["device"], "in_reply_to": d["id"], "seq": seq}}]
        for i in targets:  # M§6.5 rule 5: per-mailbox seq order, retry before later items
            q = self.pending.setdefault(i, [])
            q.append(seq)
            if len(q) == 1:
                out.append({"fanout": {"to": i, "seq": seq, "class": d["class"]}})
        return out

    def _ack(self, ident: str, seq: int) -> list:
        q = self.pending.get(ident, [])
        if not q or q[0] != seq:
            return []
        q.pop(0)
        if q:
            return [{"fanout": {"to": ident, "seq": q[0], "class": self.seq_class[q[0]]}}]
        return []

    def snapshot(self) -> dict:
        return {"epoch": self.epoch, "next_seq": self.next_seq,
                "roster": {i: sorted(d) for i, d in sorted(self.roster.items())},
                "pending": {i: list(q) for i, q in sorted(self.pending.items()) if q},
                "group_info": self.group_info}


# ---------------------------------------------------------------- mailbox (M§4.4, M§5, M§6.6, M§12.2, M§14.2)

def cursor(n: int) -> str:
    return f"c:{n:016x}"


def cursor_num(c) -> int | None:
    if not isinstance(c, str) or not c.startswith("c:") or len(c) != 18:
        return None
    try:
        return int(c[2:], 16)
    except ValueError:
        return None


class Mailbox:
    def __init__(self, ctx: dict):
        self.now = ctx["now"]
        self.owner = ctx["owner"]
        self.serves = set(ctx.get("serves", [self.owner]))
        self.devices = sorted(ctx["devices"])
        self.mode = ctx.get("mode", "sync")
        self.admit = ctx.get("admit", "grant")
        self.pending_ttl = ctx.get("pending_group_ttl", 604800)
        self.pending_max = ctx.get("pending_group_max_items", 500)
        self.groups = {g: {"hub": r["hub"], "state": r["state"], "since": self.now, "items": 0}
                       for g, r in ctx.get("groups", {}).items()}
        self.kp = {dv: {"one_time": k.get("one_time", 0), "last_resort": k.get("last_resort", False)}
                   for dv, k in ctx.get("key_packages", {}).items()}
        self.revoked: set[str] = set()
        self.items: list[dict] = []
        self.counter = 0
        self.acks: dict[str, int] = {}
        self.bound: set[str] = set()
        self.archived: dict[tuple, str] = {}
        self.intro_limit = ctx.get("intro_limit", 5)
        self.intro_window = ctx.get("intro_window", 3600)
        self.inbox_cap = ctx.get("inbox_cap", 16)
        self.intro_log: dict[str, list] = {}

    # --- helpers
    @staticmethod
    def _error(to, eid, reason):
        return [{"error": {"to": to, "in_reply_to": eid, "reason": reason}}]

    def _grant_ok(self, grant, grantee: str, target: str) -> bool:
        return (isinstance(grant, dict) and grant.get("from") == target and grant.get("to") == grantee
                and bool(MESSAGE_GRANT_SCOPES & set(grant.get("scope", [])))
                and grant.get("valid_until", 0) > self.now and grant.get("id") not in self.revoked)

    def _store(self, cls: str, group: str, **extra) -> tuple[str, list]:
        if cls == "group-info":  # M§5.2: latest per group only
            self.items = [it for it in self.items if not (it["group"] == group and it["class"] == "group-info")]
        self.counter += 1
        c = cursor(self.counter)
        self.items.append({"cursor": c, "n": self.counter, "class": cls, "group": group, **extra})
        return c, [{"push": {"to": dv, "cursor": c}} for dv in sorted(self.bound) if dv != extra.get("depositor")]

    # --- events
    def step(self, ev: dict) -> list:
        (name, e), = ev.items()
        return getattr(self, "_" + name.replace("-", "_"))(e)

    def _first_contact(self, e: dict) -> list:
        """M§14.1 (spec-gap 54): an introduction or grant deposited for an identity, under §19.4's relay rules."""
        keys = ["sender:" + e["sender_identity"], "inbox:" + e["recipient"]]
        for k in keys:  # §19.4: rate-limited per sender identity and per recipient inbox
            log = [t for t in self.intro_log.get(k, []) if t > self.now - self.intro_window]
            self.intro_log[k] = log
            if len(log) >= self.intro_limit:
                return [{"error": {"to": e["from"], "in_reply_to": e["id"], "reason": "policy.rate-limited",
                                   "retry_after": log[0] + self.intro_window - self.now}}]
        for k in keys:
            self.intro_log[k].append(self.now)
        accepted = [{"accepted": {"to": e["from"], "in_reply_to": e["id"]}}]
        if e["recipient"] not in self.serves:
            return accepted  # §19.4 anti-enumeration: accepted and dropped, indistinguishable from delivery
        pending = sum(1 for it in self.items if it["class"] == e["kind"])
        if e["kind"] == "introduction" and pending >= self.inbox_cap:
            return accepted  # §19.4 bounded inbox: held no further, silently
        c, pushes = self._store(e["kind"], "", expires_at=e["expires_at"])
        return [{"accepted": {"to": e["from"], "in_reply_to": e["id"], "cursor": c}}] + pushes

    def _advance(self, n: int) -> list:
        self.now += n
        # §19.4: a held introduction or grant is kept only until its envelope expires
        self.items = [it for it in self.items if it.get("expires_at") is None or it["expires_at"] >= self.now]
        for g in [g for g, r in self.groups.items() if r["state"] == "pending" and r["since"] + self.pending_ttl < self.now]:
            del self.groups[g]  # M§6.6: unconfirmed pending group dropped with its items
            self.items = [it for it in self.items if not (it["group"] == g and it["class"] != "archive")]
        return []

    def _welcome(self, e: dict) -> list:
        if e["recipient"] not in self.serves:
            return self._error(e["from"], e["id"], "transport.unknown-recipient")
        adder = e.get("adder_identity")
        if e.get("via_hub"):
            # M§14.2 (spec-gap 46): a hub-forwarded welcome proves its adder only by `origin`, the adder
            # device's signed deposit for this group within 300 s of the hub's; the hub connection proves nothing
            o = e.get("origin")
            if o is None or o["group"] != e["group"] or abs(o["issued_at"] - e["issued_at"]) > ORIGIN_SKEW_S:
                return self._error(e["from"], e["id"], "policy.blocked")
            adder = o["identity"]
        succ = e.get("successor_of")
        ok = (self.admit == "open" or adder == self.owner or self._grant_ok(e.get("grant"), adder, e["recipient"])
              or (succ is not None and succ in self.groups))
        if not ok:  # M§14.2
            return self._error(e["from"], e["id"], "policy.first-contact-required")
        if e["group"] not in self.groups:
            self.groups[e["group"]] = {"hub": e["hub"], "state": "pending", "since": self.now, "items": 0}
        c, pushes = self._store("welcome", e["group"])
        return [{"accepted": {"to": e["from"], "in_reply_to": e["id"], "cursor": c}}] + pushes

    def _hub_deposit(self, e: dict) -> list:
        if e["recipient"] not in self.serves:
            return self._error(e["from"], e["id"], "transport.unknown-recipient")
        reg = self.groups.get(e["group"])
        if reg is None or reg["hub"] != e["from"]:  # M§6.6
            return self._error(e["from"], e["id"], "mailbox.unknown-group")
        if e["class"] == "ephemeral":  # M§11.2: pushed to bound devices, never stored, never acknowledged
            if e.get("expires_at") is not None and e["expires_at"] < self.now:
                return []  # M§11.2: dropped at expires_at (spec-gap 49: the originating deposit's)
            return [{"push": {"to": dv, "class": "ephemeral"}} for dv in sorted(self.bound)]
        if reg["state"] == "pending" and reg["items"] >= self.pending_max:
            return self._error(e["from"], e["id"], "mailbox.quota-exceeded")
        reg["items"] += 1
        c, pushes = self._store(e["class"], e["group"], seq=e.get("seq"))
        return [{"accepted": {"to": e["from"], "in_reply_to": e["id"], "cursor": c}}] + pushes

    def _forward(self, e: dict) -> list:
        # M§5.2, M§6.6 (spec-gap 45): an owner device's deposit addressed to another service is forwarded
        # unchanged, only to the hub registered for its group; the mailbox stores nothing
        if e["identity"] != self.owner:
            return self._error(e["device"], e["id"], "policy.blocked")
        reg = self.groups.get(e["group"])
        if reg is None or reg["hub"] != e["to"]:
            return self._error(e["device"], e["id"], "mailbox.unknown-group")
        return [{"forward": {"to": e["to"], "id": e["id"]}}]

    def _sync(self, e: dict) -> list:
        dev = e["device"]
        since = e.get("since")
        n_since = 0
        if since is not None:
            n_since = cursor_num(since)
            if n_since is None or n_since > self.counter:
                return self._error(dev, e["id"], "mailbox.cursor-invalid")
        if "ack_through" in e:
            n_ack = cursor_num(e["ack_through"])
            if n_ack is None or n_ack > self.counter:
                return self._error(dev, e["id"], "mailbox.cursor-invalid")
            self.acks[dev] = max(self.acks.get(dev, 0), n_ack)
            if self.mode == "queue":  # M§4.4: deleted once every registered device has acknowledged
                floor = min(self.acks.get(dv, 0) for dv in self.devices)
                self.items = [it for it in self.items if it["n"] > floor]
        if e.get("live"):
            self.bound.add(dev)
        limit = e.get("limit", 200)
        avail = [it for it in self.items if it["n"] > n_since]
        page = avail[:limit]
        nxt = page[-1]["cursor"] if len(avail) > limit else None
        return [{"items": {"to": dev, "in_reply_to": e["id"], "cursors": [it["cursor"] for it in page], "next": nxt}}]

    def _unbind(self, e: dict) -> list:
        self.bound.discard(e["device"])
        return []

    def _config(self, e: dict) -> list:
        dev = e["device"]
        if "mode" in e and e["mode"] not in MAILBOX_MODES:
            return self._error(dev, e["id"], "mailbox.unsupported-mode")
        if "mode" in e:
            self.mode = e["mode"]
        if "admit" in e:
            self.admit = e["admit"]
        for g in e.get("groups", []):
            if g["state"] == "left":
                self.groups.pop(g["group"], None)
            elif g["group"] in self.groups:
                self.groups[g["group"]]["state"] = "joined"
            elif "hub" in g:
                self.groups[g["group"]] = {"hub": g["hub"], "state": "joined", "since": self.now, "items": 0}
        self.revoked |= set(e.get("revoked_grants", []))
        return [{"accepted": {"to": dev, "in_reply_to": e["id"]}}]

    def _archive(self, e: dict) -> list:
        dev = e["device"]
        if self.mode == "queue":  # M§12.2
            return self._error(dev, e["id"], "mailbox.unsupported-class")
        key = (e["ref_group"], e["ref_seq"])
        if key in self.archived:
            return [{"accepted": {"to": dev, "in_reply_to": e["id"], "cursor": self.archived[key], "duplicate": True}}]
        c, pushes = self._store("archive", e["ref_group"], depositor=dev)
        self.archived[key] = c
        return [{"accepted": {"to": dev, "in_reply_to": e["id"], "cursor": c}}] + pushes

    def _kp_upload(self, e: dict) -> list:
        dev = e["device"]
        if dev not in self.devices:
            return self._error(dev, e["id"], "policy.blocked")
        k = self.kp.setdefault(dev, {"one_time": 0, "last_resort": False})
        k["one_time"] = min(k["one_time"] + e.get("count", 0), KEY_PACKAGES_PER_DEVICE)
        if e.get("last_resort"):
            k["last_resort"] = True
        return [{"accepted": {"to": dev, "in_reply_to": e["id"]}}]

    def _kp_fetch(self, e: dict) -> list:
        if e["target"] not in self.serves:
            return self._error(e["from"], e["id"], "transport.unknown-recipient")
        who = e["from_identity"]
        if not (self.admit == "open" or who == e["target"] or self._grant_ok(e.get("grant"), who, e["target"])):
            return self._error(e["from"], e["id"], "policy.first-contact-required")
        served = {}
        for dv in self.devices:  # M§5.5: one per device, single use, then last resort
            k = self.kp.get(dv, {"one_time": 0, "last_resort": False})
            if k["one_time"] > 0:
                k["one_time"] -= 1
                served[dv] = "one-time"
            elif k["last_resort"]:
                served[dv] = "last-resort"
        if not served:
            return self._error(e["from"], e["id"], "mailbox.no-key-packages")
        return [{"key_packages": {"to": e["from"], "in_reply_to": e["id"], "devices": served}}]

    def snapshot(self) -> dict:
        return {"items": [it["cursor"] for it in self.items],
                "groups": {g: r["state"] for g, r in sorted(self.groups.items())},
                "key_packages": {dv: dict(k) for dv, k in sorted(self.kp.items())}}


# ---------------------------------------------------------------- tranche 2: client rules (M§6.5, M§7.2, M§7.5, M§10, M§11, M§13.2)

VOICEMAIL_REJECT_REASONS = {"user.no-answer", "user.declined", "endpoint.busy", "endpoint.unavailable"}  # M§13.2
MEDIA_KINDS = ("audio", "video")
DELIVERED_MAX_GROUP = 32      # M§10.2: no delivered receipts in larger groups
RECEIPT_MAX_TARGETS = 256     # M§10.2
READ_MIN_INTERVAL_S = 5       # M§10.3
ACTIVITY_REFRESH_S = 5        # M§11.2
GAP_TIMEOUT_S = 300           # M§6.5


def voicemail_offer(inp: dict) -> dict:
    """M§13.2: may the caller's client offer to record a voicemail after this attempt outcome?"""
    from .registry import REASONS
    vm = inp.get("voicemail")
    if not isinstance(vm, dict) or not inp.get("can_send"):
        return {"offer": False}
    out = inp.get("outcome", {})
    t, reason = out.get("type"), out.get("reason", "")
    if t == "reject":
        ok = reason in VOICEMAIL_REJECT_REASONS or (reason not in REASONS and reason.split(".")[0] == "endpoint")
    else:
        ok = t == "cancel" and reason == "session.timeout"
    if not ok:
        return {"offer": False}
    res = {"offer": True}
    if "max_duration_s" in vm:
        res["max_duration_s"] = vm["max_duration_s"]
    return res


def select_direct(candidates: list) -> dict:
    """M§7.2: converge on the lowest conversation ULID, after the §20.6 consistency check."""
    kept, discarded = [], []
    for c in candidates:
        conv = c["conversation"]
        if not U.is_valid(conv) or abs(U.timestamp_ms(conv) // 1000 - c["issued_at"]) > ULID_TOLERANCE_S:
            discarded.append(conv)
        else:
            kept.append(conv)
    return {"winner": min(kept) if kept else None, "discarded": discarded}


def check_successor(inp: dict) -> dict:
    """M§7.5: a successor is accepted only from a predecessor member re-adding predecessor members."""
    pred = set(inp["predecessor_roster"])
    if inp["creator"] in pred and set(inp["roster"]) <= pred:
        return accept()
    return reject("successor-invalid")


def select_successor(candidates: list) -> dict:
    """M§7.5: lowest group_id wins, compared as the decoded ULID, not as base64url text."""
    from .crypto import b64url_decode
    kept, discarded = [], []
    for g in candidates:
        try:
            u = b64url_decode(g).decode("ascii")
        except (ValueError, UnicodeDecodeError):
            u = None
        if u is not None and U.is_valid(u):
            kept.append((u, g))
        else:
            discarded.append(g)
    return {"winner": min(kept)[1] if kept else None, "discarded": discarded}


class Client:
    """One device's view of one conversation: receipt collapse, watermarks, and what it sends (M§10, M§11)."""

    def __init__(self, ctx: dict):
        self.now = ctx["now"]
        self.me = ctx["me"]
        self.policy = ctx.get("policy", {})
        self.members = ctx.get("member_identities", 2)
        self.content: dict[str, dict] = {}      # id -> {sender, seq, kind}
        self.timeline: list[str] = []
        self.delivered: dict[str, dict] = {}
        self.played: dict[str, dict] = {}
        self.read_seq: dict[str, int] = {}
        self.read_through: dict[str, str] = {}
        self.sent_delivered: set[str] = set()
        self.sent_played: set[str] = set()
        self.last_read_sent: int | None = None
        self.pending_read = False
        self.last_activity: dict[str, int] = {}
        self.shown: dict[str, dict[str, int]] = {}  # sender -> activity -> expires_at

    def step(self, ev: dict) -> list:
        (name, e), = ev.items()
        return getattr(self, "_" + name)(e)

    def _sync(self, e: dict) -> list:
        fresh = []
        for it in e["items"]:
            o, seq = it["object"], it["seq"]
            if o["object"] == "content":
                if o["id"] in self.content:  # M§8.5: duplicates collapse silently
                    continue
                self.content[o["id"]] = {"sender": o["sender"], "seq": seq, "kind": o["kind"]}
                self.timeline.append(o["id"])
                fresh.append(o["id"])
            elif o["object"] == "receipt":
                self._receipt(o)
        out = []
        if self.policy.get("delivered") and self.members <= DELIVERED_MAX_GROUP:
            # M§10.2: the whole batch is processed first, so a sibling's receipt in it suppresses ours
            targets = [i for i in fresh if self.content[i]["sender"] != self.me
                       and self.me not in self.delivered.get(i, {}) and i not in self.sent_delivered]
            for k in range(0, len(targets), RECEIPT_MAX_TARGETS):
                chunk = targets[k:k + RECEIPT_MAX_TARGETS]
                out.append({"send": {"to": "conversation", "receipt": "delivered", "targets": chunk}})
            self.sent_delivered |= set(targets)
        return out

    def _receipt(self, o: dict) -> None:
        kind, who = o["kind"], o["sender"]
        if kind in ("delivered", "played"):
            book = self.delivered if kind == "delivered" else self.played
            for t in o.get("targets", []):
                c = self.content.get(t)
                if c is None or c["sender"] == who:  # the content's own identity does not receipt itself
                    continue
                if kind == "played" and c["kind"] not in MEDIA_KINDS:
                    continue
                book.setdefault(t, {}).setdefault(who, o["sent_at"])  # first by seq wins
        elif kind == "read":
            c = self.content.get(o.get("through"))
            if c is not None and c["seq"] > self.read_seq.get(who, 0):  # M§10.3: monotone
                self.read_seq[who], self.read_through[who] = c["seq"], o["through"]

    def _read_send(self) -> list:
        self.last_read_sent, self.pending_read = self.now, False
        to = "conversation" if self.policy.get("read") else "personal"  # M§10.5
        return [{"send": {"to": to, "receipt": "read", "through": self.read_through[self.me]}}]

    def _read(self, e: dict) -> list:
        c = self.content.get(e["through"])
        if c is None or c["seq"] <= self.read_seq.get(self.me, 0):
            return []
        self.read_seq[self.me], self.read_through[self.me] = c["seq"], e["through"]
        if self.last_read_sent is not None and self.now - self.last_read_sent < READ_MIN_INTERVAL_S:
            self.pending_read = True
            return []
        return self._read_send()

    def _activity_in(self, e: dict) -> list:
        # M§11.2: shown until the last refresh's expires_at (spec-gap 49), cleared at once by stopped
        acts = self.shown.setdefault(e["sender"], {})
        if e["state"] == "stopped":
            acts.pop(e["activity"], None)
        elif e["expires_at"] >= self.now:
            acts[e["activity"]] = e["expires_at"]
        if not acts:
            del self.shown[e["sender"]]
        return []

    def _advance(self, n: int) -> list:
        self.now += n
        for who in list(self.shown):
            self.shown[who] = {a: t for a, t in self.shown[who].items() if t >= self.now}
            if not self.shown[who]:
                del self.shown[who]
        if self.pending_read and self.now - self.last_read_sent >= READ_MIN_INTERVAL_S:
            return self._read_send()
        return []

    def _play(self, e: dict) -> list:
        i = e["id"]
        c = self.content.get(i)
        if (c is None or c["kind"] not in MEDIA_KINDS or not self.policy.get("played")
                or self.me in self.played.get(i, {}) or i in self.sent_played):
            return []
        self.sent_played.add(i)
        return [{"send": {"to": "conversation", "receipt": "played", "targets": [i]}}]

    def _activity(self, e: dict) -> list:
        if not self.policy.get("activity"):  # M§11.2: same opt-in as read receipts
            return []
        a, state = e["activity"], e["state"]
        if state == "active":
            last = self.last_activity.get(a)
            if last is not None and self.now - last < ACTIVITY_REFRESH_S:
                return []
            self.last_activity[a] = self.now
        else:
            self.last_activity.pop(a, None)
        return [{"send": {"to": "conversation", "activity": a, "state": state}}]

    def snapshot(self) -> dict:
        return {"timeline": list(self.timeline),
                "delivered": {i: dict(m) for i, m in sorted(self.delivered.items()) if m},
                "played": {i: dict(m) for i, m in sorted(self.played.items()) if m},
                "read_through": dict(sorted(self.read_through.items())),
                "activity": {w: dict(sorted(a.items())) for w, a in sorted(self.shown.items())}}


class GapTracker:
    """M§6.5: a device holds handshake items (and anything after them) across a seq gap; rejoin on timeout."""

    def __init__(self, ctx: dict):
        self.now = ctx["now"]
        self.contiguous = ctx.get("contiguous", 0)
        self.seen: set[int] = set()
        self.held: list[int] = []
        self.gap_since: int | None = None

    def step(self, ev: dict) -> list:
        if "advance" in ev:
            self.now += ev["advance"]
            if self.held and self.now - self.gap_since >= GAP_TIMEOUT_S:
                out = [{"rejoin": {"held": list(self.held)}}]
                self.contiguous = max(self.held + list(self.seen))
                self.seen.clear()
                self.held, self.gap_since = [], None
                return out
            return []
        it = ev["item"]
        seq, cls = it["seq"], it["class"]
        if seq <= self.contiguous or seq in self.seen:
            return [{"duplicate": seq}]
        self.seen.add(seq)
        out = []
        blocked = cls == "handshake" and seq > self.contiguous + 1
        if blocked or (self.held and seq > self.held[0]):
            self.held = sorted(self.held + [seq])
            if self.gap_since is None:
                self.gap_since = self.now
            out.append({"hold": seq})
        else:
            out.append({"process": seq})
        while self.contiguous + 1 in self.seen:
            self.contiguous += 1
            self.seen.discard(self.contiguous)
        while self.held and self.held[0] <= self.contiguous:
            out.append({"process": self.held.pop(0)})
        if not self.held:
            self.gap_since = None
        return out

    def snapshot(self) -> dict:
        return {"contiguous": self.contiguous, "held": list(self.held)}


class History:
    """One device's conversation history from MLS items and archive records (M§12.2, M§12.3, M§8.5; spec-gap 51).

    Archive records under an archive key the device does not hold yet are held (a new device syncs from null and
    meets records before the personal-group welcome that brings the key) and released when the key arrives. MLS
    items from epochs before the device joined the group are skipped: their history comes from archive. Archive
    and MLS copies of one object collapse by its key; the timeline is in (group, seq) order whatever the arrival
    order. A device archives what it shows from MLS, including its own sent content, under the current key: the
    one with the greatest `created_at`, ties broken by `akid`.
    """

    def __init__(self, ctx: dict):
        self.keys = {k["akid"]: k["created_at"] for k in ctx.get("keys", [])}
        self.joined = dict(ctx.get("joined", {}))
        self.held: list[dict] = []
        self.shown: dict[str, tuple] = {}

    def step(self, ev: dict) -> list:
        (name, e), = ev.items()
        return getattr(self, "_" + name)(e)

    def _current(self):
        return max(self.keys.items(), key=lambda kv: (kv[1], kv[0]))[0] if self.keys else None

    def _show(self, e: dict) -> dict:
        if e["id"] in self.shown:
            return {"duplicate": e["id"]}
        self.shown[e["id"]] = (e["group"], e["seq"])
        return {"show": e["id"]}

    def _joined(self, e: dict) -> list:
        self.joined[e["group"]] = e["epoch"]
        return []

    def _archive_key(self, e: dict) -> list:
        self.keys[e["akid"]] = e["created_at"]
        out, keep = [], []
        for h in self.held:
            if h["akid"] == e["akid"]:
                out.append(self._show(h))
            else:
                keep.append(h)
        self.held = keep
        return out

    def _archive(self, e: dict) -> list:
        if e["akid"] not in self.keys:
            self.held.append(e)
            return [{"hold": e["cursor"]}]
        return [self._show(e)]

    def _mls(self, e: dict) -> list:
        if e["group"] in self.joined and e["epoch"] < self.joined[e["group"]]:
            return [{"prejoin": e["seq"]}]
        return self._from_mls(e)

    def _sent(self, e: dict) -> list:
        return self._from_mls(e)

    def _from_mls(self, e: dict) -> list:
        shown = self._show(e)
        out = [shown]
        if "show" in shown and self._current() is not None:
            out.append({"archive": {"group": e["group"], "seq": e["seq"], "akid": self._current()}})
        return out

    def snapshot(self) -> dict:
        order = sorted(self.shown.items(), key=lambda kv: kv[1])
        return {"timeline": [k for k, _ in order], "held": [h["cursor"] for h in self.held], "current_akid": self._current()}


SEQUENCED_CLASSES = ("handshake", "application")


class Resume:
    """M§5.4 `ack_through` and M§8.5 across a device restart (spec-gap 44).

    The state is exactly what the device holds durably: the ack cursor, per-group seq positions and
    the joined groups. Each item is processed and committed together with that state, or not at all.
    A redelivered sequenced item is recognised by its seq, never by decrypting it: MLS consumed its
    secret the first time. Holding across a seq gap is `GapTracker`'s job; traces here hold nothing.
    """

    def __init__(self, ctx: dict):
        self.cursor = ctx.get("cursor")
        self.groups = {g: {"contiguous": p["contiguous"], "seen": set(p["seen"])} for g, p in ctx.get("groups", {}).items()}
        self.joined = set(ctx.get("joined", []))

    def step(self, ev: dict) -> list:
        (name, e), = ev.items()
        return getattr(self, "_" + name)(e)

    def _duplicate(self, it: dict) -> bool:
        if it["class"] in SEQUENCED_CLASSES:
            p = self.groups.get(it["group"])
            return p is not None and (it["seq"] <= p["contiguous"] or it["seq"] in p["seen"])
        return it["class"] == "welcome" and it["group"] in self.joined

    def _items(self, e: dict) -> list:
        out = []
        for it in e["items"]:
            if it["cursor"] == e.get("crash_at"):
                out.append({"crash": it["cursor"]})  # processed in memory, never committed: rolled back
                break
            dup = self._duplicate(it)
            if not dup and it.get("sibling"):
                # spec-gap 51: a welcome for another device of this identity holds none of this device's
                # KeyPackages; it is acknowledged but is not a join, so this device's own welcome still counts
                out.append({"sibling": it["cursor"]})
                self.cursor = it["cursor"]
                continue
            out.append({"duplicate" if dup else "process": it["cursor"]})
            # commit: the cursor advances past duplicates too, so they are acknowledged
            self.cursor = it["cursor"]
            if dup:
                continue
            if it["class"] in SEQUENCED_CLASSES:
                self._position(it["group"], it["seq"])
            elif it["class"] == "welcome":
                self.joined.add(it["group"])
        return out

    def _sent(self, e: dict) -> list:
        # spec-gap 47: the hub fans a device's own item back to its identity (M§6.5 rule 5), and MLS cannot
        # decrypt a device's own message; the seq in its `accepted` marks the copy as already processed
        self._position(e["group"], e["seq"])
        return []

    def _position(self, group: str, seq: int) -> None:
        p = self.groups.setdefault(group, {"contiguous": 0, "seen": set()})
        if seq > p["contiguous"]:
            p["seen"].add(seq)
        while p["contiguous"] + 1 in p["seen"]:
            p["contiguous"] += 1
            p["seen"].discard(p["contiguous"])

    def _sync(self, _e: dict) -> list:
        s = {"since": self.cursor}
        if self.cursor is not None:
            s["ack_through"] = self.cursor  # never ahead of what is committed
        return [{"sync": s}]

    def _restart(self, e: dict) -> list:
        self.__init__(self.snapshot())  # only durable state survives
        return self._sync(e)

    def _cursor_invalid(self, e: dict) -> list:
        self.cursor = None  # M§5.4: re-sync from null; seq positions and joined groups are kept
        return self._sync(e)

    def snapshot(self) -> dict:
        return {"cursor": self.cursor,
                "groups": {g: {"contiguous": p["contiguous"], "seen": sorted(p["seen"])} for g, p in sorted(self.groups.items())},
                "joined": sorted(self.joined)}


# ---------------------------------------------------------------- tranche 3: the MLS layer (M§6.2, M§6.3, M§8.4, M§11.1, M§12.2)

EXT_DSIP_DELEGATION = 0xF0D1   # M§17: private-use MLS ExtensionType (LeafNode) until registered
EXT_DSIP_CONVERSATION = 0xF0D2  # M§17: private-use MLS ExtensionType (GroupContext) until registered
CREDENTIAL_BASIC = 0x0001      # RFC 9420 CredentialType basic
MESSAGING_CAPABILITY = "dsip.messaging"  # M§6.2 (spec-gap 39)
NONCE_LEN, TAG_LEN = 12, 16


def vl_len(n: int) -> bytes:
    """RFC 9420 §2.1.2 variable-length vector length: minimal 1-, 2- or 4-byte QUIC-style integer."""
    if n < 1 << 6:
        return bytes([n])
    if n < 1 << 14:
        return (0x4000 | n).to_bytes(2, "big")
    if n < 1 << 30:
        return (0x80000000 | n).to_bytes(4, "big")
    raise ValueError("vector too long for MLS")


def encode_extension(ext_type: int, data: bytes) -> bytes:
    return ext_type.to_bytes(2, "big") + vl_len(len(data)) + data


def decode_extension(b: bytes) -> dict:
    if len(b) < 3:
        return reject("mls-truncated")
    prefix = b[2] >> 6
    if prefix == 3:  # 8-byte lengths exceed MLS's 30-bit bound
        return reject("mls-length-invalid")
    n = {0: 1, 1: 2, 2: 4}[prefix]
    if len(b) < 2 + n:
        return reject("mls-truncated")
    length = int.from_bytes(b[2:2 + n], "big") & ((1 << (8 * n - 2)) - 1)
    if (n == 2 and length < 1 << 6) or (n == 4 and length < 1 << 14):
        return reject("mls-length-non-minimal")
    data = b[2 + n:2 + n + length]
    if len(data) < length:
        return reject("mls-truncated")
    if len(b) > 2 + n + length:
        return reject("mls-trailing-bytes")
    return accept(extension_type=int.from_bytes(b[:2], "big"), data_hex=data.hex())


def check_mls_credential(inp: dict, ctx: dict) -> dict:
    """M§6.2: the DSIP authentication service for an MLS leaf."""
    from . import envelope as E
    from .crypto import public_from_did_key
    cred = inp["credential"]
    if cred.get("credential_type") != CREDENTIAL_BASIC:
        return reject("credential-type")
    try:
        device = bytes.fromhex(cred["identity_hex"]).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return reject("credential-identity")
    import re
    if not re.match(r"^did:[a-z0-9]+:[A-Za-z0-9.%_:-]+$", device):
        return reject("credential-identity")
    exts = [e for e in inp.get("extensions", []) if e["extension_type"] == EXT_DSIP_DELEGATION]
    if not exts:
        return reject("delegation-missing")
    if len(exts) > 1:
        return reject("delegation-invalid")
    try:
        parts = bytes.fromhex(exts[0]["data_hex"]).decode("ascii").split(".")
    except (ValueError, UnicodeDecodeError):
        return reject("delegation-invalid")
    if len(parts) != 3:
        return reject("delegation-invalid")
    deleg = {"protected": parts[0], "payload": parts[1], "signature": parts[2]}
    names = E._names(deleg)
    if names is None or names[1] != device or not isinstance(names[0], str):
        return reject("delegation-invalid")
    v = E.verify_delegation(deleg, names[0], device, E.Context.from_vector(ctx), capability=MESSAGING_CAPABILITY)
    if not v.ok:
        return reject(v.code)
    try:
        pub = public_from_did_key(device)
    except Exception:
        pub = None
    if pub is None or pub.hex() != inp["signature_key_hex"]:  # M§6.2: leaf key = the device's Ed25519 key
        return reject("credential-key-mismatch")
    return accept(identity=names[0], device=device)


def check_conversation_bytes(data: bytes) -> dict:
    """M§6.3: dsip_conversation extension data is UTF-8 JSON under §10.3, then the schema."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return reject("payload-not-utf8")
    try:
        obj = json.loads(text)
    except ValueError:
        return reject("payload-not-json")
    if not isinstance(obj, dict):
        return reject("payload-not-json")
    if has_float(obj):
        return reject("payload-float")
    return check_conversation_ext(obj)


def seal_aad(inp: dict) -> bytes:
    """AAD by use: blob none (M§8.4); activity group_id ‖ epoch (M§11.1); archive group_id ‖ seq (M§12.2)."""
    use = inp["use"]
    if use == "blob":
        return b""
    counter = inp["epoch"] if use == "activity" else inp["seq"]
    return bytes.fromhex(inp["group_hex"]) + counter.to_bytes(8, "big")


def seal(inp: dict) -> dict:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key, nonce = bytes.fromhex(inp["key_hex"]), bytes.fromhex(inp["nonce_hex"])
    ct = AESGCM(key).encrypt(nonce, bytes.fromhex(inp["plaintext_hex"]), seal_aad(inp) or None)
    return {"sealed_hex": (nonce + ct).hex()}


def open_sealed(inp: dict) -> dict:
    import hashlib
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    stored = bytes.fromhex(inp["sealed_hex"])
    if inp["use"] == "blob":  # M§8.4 rule 7: size and hash before decrypting
        if len(stored) != inp["size"]:
            return reject("blob-size-mismatch")
        if hashlib.sha256(stored).hexdigest() != inp["sha256"]:
            return reject("blob-hash-mismatch")
    if len(stored) < NONCE_LEN + TAG_LEN:
        return reject("sealed-too-short")
    try:
        pt = AESGCM(bytes.fromhex(inp["key_hex"])).decrypt(stored[:NONCE_LEN], stored[NONCE_LEN:], seal_aad(inp) or None)
    except InvalidTag:
        return reject("aead-open-failed")
    return accept(plaintext_hex=pt.hex())


def registration_on_removal(inp: dict) -> dict:
    """M§5.7, M§6.6 (spec-gap 53): a group registration belongs to the identity, so a device removed from a group
    ends it (`left`) only when no leaf of its identity remains in the group."""
    return {"left": inp["me"] not in inp["remaining_identities"]}


# ---------------------------------------------------------------- first contact: HPKE and sealed introductions (M§6.9, M§14.1)

import hashlib as _hashlib
import hmac as _hmac

HPKE_KEM_ID, HPKE_KDF_ID, HPKE_AEAD_ID = 0x0020, 0x0001, 0x0001  # DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM
SEALED_ALG = "hpke-base-x25519-sha256-aes128gcm"
SEALED_INFO = b"dsip sealed introduction v1"
PURPOSE_MAX_CHARS = 280  # §19.4


def _i2osp(n: int, w: int) -> bytes:
    return n.to_bytes(w, "big")


_KEM_SUITE = b"KEM" + _i2osp(HPKE_KEM_ID, 2)
_HPKE_SUITE = b"HPKE" + _i2osp(HPKE_KEM_ID, 2) + _i2osp(HPKE_KDF_ID, 2) + _i2osp(HPKE_AEAD_ID, 2)


def _labeled_extract(salt: bytes, label: bytes, ikm: bytes, suite: bytes) -> bytes:
    return _hmac.new(salt or b"\0" * 32, b"HPKE-v1" + suite + label + ikm, _hashlib.sha256).digest()


def _labeled_expand(prk: bytes, label: bytes, info: bytes, n: int, suite: bytes) -> bytes:
    labeled = _i2osp(n, 2) + b"HPKE-v1" + suite + label + info
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = _hmac.new(prk, t + labeled + bytes([i]), _hashlib.sha256).digest()
        out += t
        i += 1
    return out[:n]


def _x25519(sk: bytes, pk: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    return X25519PrivateKey.from_private_bytes(sk).exchange(X25519PublicKey.from_public_bytes(pk))


def x25519_public(sk: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    return X25519PrivateKey.from_private_bytes(sk).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _shared_secret(dh: bytes, enc: bytes, pk_r: bytes) -> bytes:
    prk = _labeled_extract(b"", b"eae_prk", dh, _KEM_SUITE)
    return _labeled_expand(prk, b"shared_secret", enc + pk_r, 32, _KEM_SUITE)


def _key_schedule(shared: bytes, info: bytes) -> tuple:
    ctx = _i2osp(0, 1) + _labeled_extract(b"", b"psk_id_hash", b"", _HPKE_SUITE) + _labeled_extract(b"", b"info_hash", info, _HPKE_SUITE)
    secret = _labeled_extract(shared, b"secret", b"", _HPKE_SUITE)
    return _labeled_expand(secret, b"key", ctx, 16, _HPKE_SUITE), _labeled_expand(secret, b"base_nonce", ctx, 12, _HPKE_SUITE)


def hpke_seal(pk_r: bytes, info: bytes, aad: bytes, pt: bytes, sk_e: bytes) -> tuple:
    """RFC 9180 base mode, single shot, with the ephemeral key supplied (generator use: deterministic vectors)."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    enc = x25519_public(sk_e)
    key, nonce = _key_schedule(_shared_secret(_x25519(sk_e, pk_r), enc, pk_r), info)
    return enc, AESGCM(key).encrypt(nonce, pt, aad or None)


def hpke_open(enc: bytes, sk_r: bytes, info: bytes, aad: bytes, ct: bytes):
    """RFC 9180 base mode, single shot; None when it does not open."""
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    try:
        pk_r = x25519_public(sk_r)
        key, nonce = _key_schedule(_shared_secret(_x25519(sk_r, enc), enc, pk_r), info)
        return AESGCM(key).decrypt(nonce, ct, aad or None)
    except (InvalidTag, ValueError):
        return None


def hpke_derive_sk(ikm: bytes) -> bytes:
    """RFC 9180 §7.1.3 DeriveKeyPair for X25519."""
    return _labeled_expand(_labeled_extract(b"", b"dkp_prk", ikm, _KEM_SUITE), b"sk", b"", 32, _KEM_SUITE)


def x25519_from_ed25519_seed(seed: bytes) -> bytes:
    """M§6.9: the X25519 key agreement key of an Ed25519 key, as the did:key method derives it (clamped by X25519)."""
    return _hashlib.sha512(seed).digest()[:32]


def sealed_aad(p: dict) -> bytes:
    """M§14.1: id ‖ 0x00 ‖ from ‖ 0x00 ‖ to, so a sealed body cannot be spliced into another introduction."""
    return p["id"].encode() + b"\0" + p["from"].encode() + b"\0" + p["to"].encode()


def check_introduction(p: dict) -> dict:
    """M§14.1: an introduction under the profile — core §19.4 shape plus `sealed`, never both `purpose` and `sealed`."""
    if not schema_ok("introduction", p):
        return reject("schema-invalid")
    if "purpose" in p and "sealed" in p:
        return reject("introduction-purpose-and-sealed")
    if "sealed" in p and p["sealed"]["alg"] != SEALED_ALG:
        return reject("sealed-alg-unsupported")
    return accept(effective={"sealed": "sealed" in p})


def open_sealed_introduction(p: dict, recipient_seed: bytes) -> dict:
    v = check_introduction(p)
    if v["verdict"] != "accept":
        return v
    if "sealed" not in p:
        return accept(purpose=p.get("purpose"))
    sk = x25519_from_ed25519_seed(recipient_seed)
    from .crypto import b64url_decode
    pt = hpke_open(b64url_decode(p["sealed"]["enc"]), sk, SEALED_INFO, sealed_aad(p), b64url_decode(p["sealed"]["ct"]))
    if pt is None:
        return reject("sealed-open-failed")
    try:
        body = json.loads(pt)
    except ValueError:
        return reject("sealed-plaintext-invalid")
    if not isinstance(body, dict) or set(body) != {"purpose"} or not isinstance(body["purpose"], str):
        return reject("sealed-plaintext-invalid")
    if len(body["purpose"]) > PURPOSE_MAX_CHARS:
        return reject("purpose-too-long")
    return accept(purpose=body["purpose"])


# ---------------------------------------------------------------- blob endpoint (M§5.6, M§8.4)

def blob_put(inp: dict) -> dict:
    """M§5.6: what a mailbox answers to `PUT {blob_endpoint}/{sha256}` (spec-gap 48 for statuses and tokens).

    `authorization` is the verified `Authorization: DSIP` envelope — `{identity, payload}` once the envelope
    pipeline, the device's delegation and the message rules (M§5.1) have passed — or null. Checks run in the
    order a server can make them: credential, addressee, served identity, URL binding, declared size (before
    reading the body), then the body itself; a blob already stored under that hash is an idempotent success.
    """
    mbx, req, auth = inp["mailbox"], inp["request"], inp.get("authorization")
    if auth is None:
        return {"status": 401, "reason": "policy.blocked"}
    p = auth["payload"]
    if p["to"] != mbx["did"]:  # an authorization minted for another mailbox
        return {"status": 403, "reason": "policy.blocked"}
    if auth["identity"] not in mbx["serves"]:  # M§5.6: the device must be delegated by an identity it serves
        return {"status": 403, "reason": "transport.unknown-recipient"}
    if req["path_sha256"] != p["sha256"]:  # the URL names the authorized blob
        return {"status": 400, "reason": "policy.blocked"}
    if p["size"] > mbx["max_blob_bytes"]:  # M§16
        return {"status": 413, "reason": "mailbox.object-too-large"}
    if req["body_size"] != p["size"] or req["body_sha256"] != p["sha256"]:  # M§5.6
        return {"status": 400, "reason": "mailbox.blob-mismatch"}
    if p["sha256"] in inp.get("stored", []):
        return {"status": 200, "accepted": {"in_reply_to": p["id"], "duplicate": True}}
    return {"status": 201, "accepted": {"in_reply_to": p["id"]}}


def blob_get(inp: dict) -> dict:
    """M§8.4 rule 5: the hash is a capability; the mailbox serves exactly what it stored under it."""
    return {"status": 200 if inp["path_sha256"] in inp.get("stored", []) else 404}


# ---------------------------------------------------------------- discovery (M§4.2, §8.1)

def select_mailbox(inp: dict) -> dict:
    """M§4.2: the DID document is authoritative; hints serve only identities with no document entry.

    Entries are usable when they satisfy the service schema (wss, bindings, mailbox DID) and
    advertise `messaging/1.0`. Order is by `priority` (absent = 0), stable within a priority. The
    selected mailbox is the first usable one that accepts a connection; the owner's devices sync
    every usable one.
    """
    doc, hints = inp.get("document_entries") or [], inp.get("hint_entries") or []
    source = "did-document" if doc else ("hint" if hints else None)
    entries = doc or hints                      # §8.1 rule 6: no falling back to hints past a document
    usable, discarded = [], []
    for e in entries:
        if not schema_ok("mailbox-service", e) or MESSAGING_PROFILE not in (e.get("profiles") or []):
            discarded.append(e.get("uri"))
        else:
            usable.append(e)
    usable.sort(key=lambda e: e.get("priority", 0))   # Python's sort is stable
    order = [e["mailbox"] for e in usable]
    reachable = inp.get("reachable")
    selected = next((m for m in order if reachable is None or m in reachable), None)
    return {"source": source, "selected": selected, "order": order, "sync_targets": order, "discarded": discarded}


def mailbox_switch(inp: dict) -> dict:
    """M§4.2, M§15.4: an established conversation's mailbox never moves on a hint alone."""
    established, candidate = inp["established"], inp["candidate"]
    if candidate["mailbox"] == established["mailbox"]:
        return {"switch": False, "reason": "unchanged"}
    if candidate.get("source") != "did-document":
        return {"switch": False, "reason": "hint-sourced"}
    return {"switch": True, "reason": "did-document"}


# ---------------------------------------------------------------- runner

def run(v: dict) -> dict:
    inp = v["input"]
    check = inp.get("check")
    if check == "payload":
        name = inp["schema"]
        return accept() if schema_ok(name, inp["payload"]) else reject("schema-invalid")
    if check == "message":
        return check_message(inp["payload"])
    if check == "object":
        return check_object(inp["object"], v["context"])
    if check == "conversation-ext":
        return check_conversation_ext(inp["extension"])
    if check == "mailbox-select":
        return select_mailbox(inp)
    if check == "mailbox-switch":
        return mailbox_switch(inp)
    if check == "mls-extension-encode":
        return {"hex": encode_extension(inp["extension_type"], bytes.fromhex(inp["data_hex"])).hex()}
    if check == "mls-extension-decode":
        return decode_extension(bytes.fromhex(inp["hex"]))
    if check == "mls-credential":
        return check_mls_credential(inp, v["context"])
    if check == "mls-conversation-bytes":
        return check_conversation_bytes(bytes.fromhex(inp["data_hex"]))
    if check == "seal":
        return seal(inp)
    if check == "open":
        return open_sealed(inp)
    if check == "hpke-open":
        pt = hpke_open(bytes.fromhex(inp["enc_hex"]), bytes.fromhex(inp["sk_r_hex"]), bytes.fromhex(inp["info_hex"]),
                       bytes.fromhex(inp["aad_hex"]), bytes.fromhex(inp["ct_hex"]))
        return reject("hpke-open-failed") if pt is None else accept(plaintext_hex=pt.hex())
    if check == "hpke-derive-key-pair":
        sk = hpke_derive_sk(bytes.fromhex(inp["ikm_hex"]))
        return {"sk_hex": sk.hex(), "pk_hex": x25519_public(sk).hex()}
    if check == "x25519-key-agreement":
        sk = x25519_from_ed25519_seed(bytes.fromhex(inp["ed25519_seed_hex"]))
        return {"x25519_pk_hex": x25519_public(sk).hex()}
    if check == "introduction":
        return check_introduction(inp["payload"])
    if check == "sealed-introduction-open":
        return open_sealed_introduction(inp["payload"], bytes.fromhex(inp["recipient_ed25519_seed_hex"]))
    if check == "registration-on-removal":
        return registration_on_removal(inp)
    if check == "blob-put":
        return blob_put(inp)
    if check == "blob-get":
        return blob_get(inp)
    if check == "voicemail-offer":
        return voicemail_offer(inp)
    if check == "direct-select":
        return select_direct(inp["candidates"])
    if check == "successor-check":
        return check_successor(inp)
    if check == "successor-select":
        return select_successor(inp["candidates"])
    if check in ("hub-trace", "mailbox-trace", "client-trace", "gap-trace", "resume-trace", "history-trace"):
        comp = {"hub-trace": Hub, "mailbox-trace": Mailbox, "client-trace": Client, "gap-trace": GapTracker,
                "resume-trace": Resume, "history-trace": History}[check](v["context"])
        steps = []
        for st in inp["steps"]:
            emit = comp.step(st["event"])
            steps.append({"emit": emit, "state": comp.snapshot()})
        return {"steps": steps}
    return {"error": f"unknown messaging check {check}"}
