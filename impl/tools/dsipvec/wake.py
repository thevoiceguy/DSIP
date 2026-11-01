"""Wake Profile (draft, `wake/0.1`) — reference for the `wake/` vectors.

Spec: W§3 (enrolment at the gateway), W§4 (the registration, `wake-register`, when a registration ends), W§5 (when a
waker wakes, the `wake`, the gateway's checks and what it forwards), W§6 (the sealed hint). Contract:
impl/vectors/README.md, kind `wake`.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from . import envelope as E
from .crypto import b64url_decode

REPO_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_DIR = REPO_ROOT / "v1.0" / "dsip-wake-schemas-draft" / "schemas"

W_REGISTRATION_S = 2_592_000  # W§7
W_COALESCE_S = 60             # W§7
W_CALL_ENDED_S = 60           # W§7
FUTURE_S = 300                # W§4.2 step 3: issued_at at most the replay window ahead (§12.9)
HINT_ALG = "hpke-base-x25519-sha256-aes128gcm"  # W§6, M§6.9's suite
HINT_INFO = b"dsip wake hint v1"
HINT_BYTES = 256
CALL_KINDS = ("call", "call-ended")


@lru_cache(maxsize=None)
def _validator(name: str):
    from .schema import Validator
    return Validator(json.loads((SCHEMA_DIR / f"{name}.schema.json").read_text()))


def schema_ok(name: str, value) -> bool:
    return not any(True for _ in _validator(name).iter_errors(value))


def reject(code: str, reason: str | None = None) -> dict:
    out = {"verdict": "reject", "code": code}
    if reason:
        out["reason"] = reason
    return out


def refuse(token: str) -> dict:
    """A W§8 refusal: the code is the token's condition."""
    return reject(token.split(".", 1)[1], token)


def verify_registration(reg, now: int) -> dict | None:
    """W§4.2 step 1: the credential's signature by a key of `key`, its payload's schema. No replay window (W§4.1)."""
    v, ver = E.verify_raw(reg, E.Context(now=now), core_shape=False)
    if not v.ok:
        return None
    p = ver.payload
    if not schema_ok("wake-registration", p) or ver.signer_did != p["key"]:
        return None
    return p


def enrol(i: dict, ctx: dict) -> dict:
    """W§3: the gateway's reading of a verified `wake-enrol`."""
    p = i["enrol"]
    if not schema_ok("wake-enrol", p):
        return reject("schema-invalid")
    if {"provider": p["provider"], "app": p["app"]} not in ctx["apps"]:
        return refuse("wake.unsupported-app")
    out = {"key": p["from"], "provider": p["provider"], "app": p["app"], "token": p["token"]}
    if p["provider"] == "apns":
        out["environment"] = p.get("environment", "production")
    return {"verdict": "accept", "enrolment": out}


def register(i: dict, ctx: dict) -> dict:
    """W§4.2: the waker's checks on a verified `wake-register`, in order."""
    p, now = i["register"], ctx["now"]
    if not schema_ok("wake-register", p):
        return reject("schema-invalid")
    if p.get("remove") is True:
        return {"verdict": "accept", "removed": True}
    r = verify_registration(p["registration"], now)
    if r is None:
        return refuse("wake.registration-invalid")
    if r["waker"] != ctx["waker"]:
        return refuse("wake.waker-mismatch")
    if not (r["issued_at"] < r["expires_at"] <= r["issued_at"] + W_REGISTRATION_S) or r["expires_at"] <= now \
            or r["issued_at"] > now + FUTURE_S:
        return refuse("wake.registration-invalid")
    if "gateways" in ctx and r["gateway"] not in ctx["gateways"]:
        return refuse("wake.gateway-unknown")
    out = {"device": i["device"], "key": r["key"], "gateway": r["gateway"], "handle": r["handle"],
           "expires_at": r["expires_at"]}
    if "kinds" in p:
        out["kinds"] = sorted(set(p["kinds"]))
    if "seal_key" in p:
        out["seal_key"] = p["seal_key"]
    return {"verdict": "accept", "registration": out}


def gateway_wake(i: dict, ctx: dict) -> dict:
    """W§5.3: the gateway's checks on a verified `wake`, and the push it forwards."""
    p, now = i["wake"], ctx["now"]
    if not schema_ok("wake", p):
        return reject("schema-invalid")
    r = verify_registration(p["registration"], now)
    h = ctx["handles"].get(r["handle"]) if r is not None else None
    if (h is None or r["key"] != h["key"] or r["waker"] != i["signer"] or r["gateway"] != ctx["gateway"]
            or r["expires_at"] <= now):
        return refuse("wake.not-authorized")
    if p["deliver_by"] <= now:
        return refuse("wake.expired")
    data = {"kind": p["kind"], "waker": i["signer"]}
    for k in ("session", "sealed"):
        if k in p:
            data[k] = p[k]
    fwd = {"provider": h["provider"], "app": h["app"], "token": h["token"],
           "class": "call" if p["kind"] in CALL_KINDS else "message",  # W§8.2: an unknown kind is `message`
           "deliver_by": p["deliver_by"], "data": {"dsip-wake": data}}
    if h["provider"] == "apns":
        fwd["environment"] = h.get("environment", "production")
    return {"verdict": "accept", "forward": fwd}


def open_hint(i: dict) -> dict:
    """W§6: the device opens a `call` wake's sealed hint."""
    from .messaging import hpke_open
    s = i["sealed"]
    if s["alg"] != HINT_ALG:
        return reject("sealed-alg-unsupported")
    try:
        enc, ct = b64url_decode(s["enc"]), b64url_decode(s["ct"])
    except ValueError:
        return reject("sealed-open-failed")
    pt = hpke_open(enc, bytes.fromhex(i["secret_hex"]), HINT_INFO, i["session"].encode("utf-8"), ct)
    if pt is None:
        return reject("sealed-open-failed")
    bad = reject("sealed-plaintext-invalid")
    if len(pt) != HINT_BYTES:
        return bad
    from .wire import _IntOnly, FloatFound
    try:
        hint = json.loads(pt.rstrip(b" ").decode("utf-8"), cls=_IntOnly)
    except (UnicodeDecodeError, ValueError, FloatFound, RecursionError):
        return bad
    if not schema_ok("wake-hint", hint):
        return bad
    return {"verdict": "accept", "hint": hint}


class Waker:
    """A relay's or a mailbox's wake state (W§4.3, W§5.1): registrations, bindings, what it holds, and the wakes it
    sends. Every event carries `at`; what has expired by then is settled first: held invites, then registrations."""

    def __init__(self, ctx: dict):
        self.component = ctx["component"]
        self.regs: dict[str, dict] = {}
        self.bound: set[str] = set()
        self.held: dict[str, dict] = {}       # session → {expires_at, devices (held for, unbound), woken}
        self.last_message: dict[str, int] = {}

    def _live(self, d: str, at: int) -> bool:
        return d in self.regs and self.regs[d]["expires_at"] > at

    def _wants(self, d: str, kind: str) -> bool:
        k = self.regs[d].get("kinds")
        return k is None or kind in k

    def _end(self, d: str, cause: str) -> list:
        if d not in self.regs:
            return []
        del self.regs[d]
        return [{"ended": {"device": d, "cause": cause}}]

    def _call_ended(self, sid: str, when: int) -> list:
        """W§5.1: the held invite `sid` stopped being held at `when` (its drop, or its expiry)."""
        h = self.held.pop(sid)
        return [{"wake": {"device": d, "kind": "call-ended", "session": sid, "deliver_by": when + W_CALL_ENDED_S}}
                for d in sorted(h["woken"] & h["devices"]) if self._live(d, when) and self._wants(d, "call-ended")]

    def step(self, ev: dict) -> list:
        at = ev["at"]
        out = []
        for sid in sorted(self.held):
            if self.held[sid]["expires_at"] <= at:
                out += self._call_ended(sid, self.held[sid]["expires_at"])
        for d in sorted(self.regs):
            if self.regs[d]["expires_at"] <= at:
                out += self._end(d, "expired")
        if "register" in ev:
            r = ev["register"]
            self.regs[r["device"]] = {"identity": r["identity"], "expires_at": r["expires_at"],
                                      **({"kinds": list(r["kinds"])} if "kinds" in r else {})}
        elif "remove" in ev:
            out += self._end(ev["remove"], "removed")
        elif "revoke" in ev:
            out += self._end(ev["revoke"], "revoked")
        elif "forget" in ev:
            out += self._end(ev["forget"], "forgotten")
        elif "bind" in ev:
            d = ev["bind"]
            self.bound.add(d)
            for h in self.held.values():  # §13.3: flushed on the binding; no longer held for it
                h["devices"].discard(d)
                h["woken"].discard(d)
            self.last_message.pop(d, None)
        elif "unbind" in ev:
            self.bound.discard(ev["unbind"])
        elif "hold" in ev:
            assert self.component == "relay", ev
            x = ev["hold"]
            if x["expires_at"] > at:
                h = self.held.setdefault(x["session"], {"expires_at": x["expires_at"], "devices": set(), "woken": set()})
                for d in sorted(set(x["devices"])):
                    if d in self.bound:
                        continue
                    h["devices"].add(d)
                    if d not in h["woken"] and self._live(d, at) and self._wants(d, "call"):
                        h["woken"].add(d)
                        out.append({"wake": {"device": d, "kind": "call", "session": x["session"],
                                             "deliver_by": x["expires_at"]}})
        elif "drop" in ev:
            assert self.component == "relay", ev
            if ev["drop"] in self.held:
                out += self._call_ended(ev["drop"], at)
        elif "store" in ev:
            assert self.component == "mailbox", ev
            x = ev["store"]
            if x.get("class") != "ephemeral":
                for d in sorted(self.regs):
                    if (self.regs[d]["identity"] != x["identity"] or d in self.bound or not self._live(d, at)
                            or not self._wants(d, "message")):
                        continue
                    if d in self.last_message and at - self.last_message[d] < W_COALESCE_S:
                        continue
                    self.last_message[d] = at
                    out.append({"wake": {"device": d, "kind": "message", "deliver_by": at + W_COALESCE_S}})
        elif "answer" in ev:
            a = ev["answer"]
            if a["reason"].startswith("wake."):  # W§4.3, W§8.1: every wake.* answer, known or not, ends it
                out += self._end(a["device"], "gateway")
        elif "tick" in ev:
            pass
        else:
            raise ValueError(ev)
        return out


def run(v: dict):
    i, ctx = v["input"], v.get("context") or {}
    check = i.get("check")
    if check == "schema":
        return {"verdict": "accept"} if schema_ok(i["schema"], i["value"]) else reject("schema-invalid")
    if check == "enrol":
        return enrol(i, ctx)
    if check == "register":
        return register(i, ctx)
    if check == "gateway":
        return gateway_wake(i, ctx)
    if check == "open-hint":
        return open_hint(i)
    w = Waker(ctx)
    return [{"emit": w.step(st["event"]), "registrations": sorted(w.regs)} for st in i["steps"]]
