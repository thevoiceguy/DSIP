"""Messaging Profile 1.0 reference semantics (v0.8 draft, cited M§n).

Spec: `v0.8/dsip-messaging-profile-v0.8-draft.md`. Written before any Rust implementation; the
`messaging/` vectors pin this module's choices and `dsip-messaging` mirrors it.

Checks (`input.check`):
- `payload`  JSON Schema shape of a profile message or object (M§5, M§8).
- `message`  schema + stateless semantic rules for a profile message payload (M§5).
- `object`   schema + stateless rules for a decrypted content object (M§8, M§10, M§11, M§12).
- `hub-trace`, `mailbox-trace`  scripted state traces of the hub (M§6.5–M§6.8, M§7.3, M§9.3,
  M§11.2) and the mailbox (M§4.4, M§5.4–M§5.7, M§6.6, M§12.2, M§14.2).

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

MESSAGE_SCHEMAS = ["deposit", "accepted", "sync", "items", "key-packages", "key-package-fetch", "blob-put",
                   "mailbox-config"]
OBJECT_SCHEMAS = ["content", "receipt", "activity", "archive-key", "call-event", "archive-record"]

# Registries (M§17). Membership is checked here; the schemas only check token shape.
DEPOSIT_CLASSES = {"handshake", "application", "welcome", "group-info", "ephemeral", "archive"}
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
}
DEPOSIT_ALLOWED = {
    "handshake": {"mls", "seq", "welcome", "group_info", "ratchet_tree_blob", "grants"},
    "application": {"mls", "seq", "blobs"},
    "welcome": {"mls", "hub", "grants", "origin", "successor_of", "ratchet_tree_blob"},
    "group-info": {"mls", "ratchet_tree_blob"},
    "ephemeral": {"sealed"},
    "archive": {"archive", "akid", "ref_group", "ref_seq"},
}
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
        if o["conversation"] != ctx.get("conversation"):
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
        if cls not in ("handshake", "application", "ephemeral"):
            return self._error(d, "mailbox.unsupported-class")
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
        before = set(self.roster)
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
            out += [{"fanout": {"to": i, "class": "welcome"}} for i in sorted(set(self.roster) - before)]
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
                "pending": {i: list(q) for i, q in sorted(self.pending.items()) if q}}


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

    # --- helpers
    @staticmethod
    def _error(to, eid, reason):
        return [{"error": {"to": to, "in_reply_to": eid, "reason": reason}}]

    def _grant_ok(self, grant, grantee: str, target: str) -> bool:
        return (isinstance(grant, dict) and grant.get("from") == target and grant.get("to") == grantee
                and bool(MESSAGE_GRANT_SCOPES & set(grant.get("scope", [])))
                and grant.get("valid_until", 0) > self.now and grant.get("id") not in self.revoked)

    def _store(self, cls: str, group: str, **extra) -> tuple[str, list]:
        self.counter += 1
        c = cursor(self.counter)
        self.items.append({"cursor": c, "n": self.counter, "class": cls, "group": group, **extra})
        return c, [{"push": {"to": dv, "cursor": c}} for dv in sorted(self.bound) if dv != extra.get("depositor")]

    # --- events
    def step(self, ev: dict) -> list:
        (name, e), = ev.items()
        return getattr(self, "_" + name.replace("-", "_"))(e)

    def _advance(self, n: int) -> list:
        self.now += n
        for g in [g for g, r in self.groups.items() if r["state"] == "pending" and r["since"] + self.pending_ttl < self.now]:
            del self.groups[g]  # M§6.6: unconfirmed pending group dropped with its items
            self.items = [it for it in self.items if not (it["group"] == g and it["class"] != "archive")]
        return []

    def _welcome(self, e: dict) -> list:
        if e["recipient"] not in self.serves:
            return self._error(e["from"], e["id"], "transport.unknown-recipient")
        adder = e["adder_identity"]
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
            return [{"push": {"to": dv, "class": "ephemeral"}} for dv in sorted(self.bound)]
        if reg["state"] == "pending" and reg["items"] >= self.pending_max:
            return self._error(e["from"], e["id"], "mailbox.quota-exceeded")
        reg["items"] += 1
        c, pushes = self._store(e["class"], e["group"], seq=e.get("seq"))
        return [{"accepted": {"to": e["from"], "in_reply_to": e["id"], "cursor": c}}] + pushes

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
    if check in ("hub-trace", "mailbox-trace"):
        comp = (Hub if check == "hub-trace" else Mailbox)(v["context"])
        steps = []
        for st in inp["steps"]:
            emit = comp.step(st["event"])
            steps.append({"emit": emit, "state": comp.snapshot()})
        return {"steps": steps}
    return {"error": f"unknown messaging check {check}"}
