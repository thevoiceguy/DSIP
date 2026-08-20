"""Shared payload builders and vector assembly helpers."""
from __future__ import annotations

import copy

from .. import FORMAT_VERSION
from .. import fixtures as F
from .. import envelope as E
from .. import ulid as U

NOW = F.NOW

MEDIA_OFFER = [{"type": "audio", "direction": "sendrecv",
                "codecs": [{"id": "codec:audio/opus", "sample_rates": [48000], "channels": [1, 2]},
                           {"id": "codec:audio/pcmu", "sample_rates": [8000], "channels": [1]}]},
               {"type": "video", "direction": "sendrecv",
                "codecs": [{"id": "codec:video/h264", "profiles": ["baseline"]}]}]
TRANSPORTS = [{"id": "transport:webrtc", "ice": "trickle"}, {"id": "transport:rtp-sdes"}]
AUDIO_SELECTION = [{"type": "audio", "direction": "sendrecv", "codecs": [{"id": "codec:audio/opus"}]}]
ONE_TRANSPORT = [{"id": "transport:webrtc"}]


def uid(label: str, at: int = NOW, offset_ms: int = 0) -> str:
    """Deterministic ULID whose timestamp component matches `at` (seconds)."""
    return U.deterministic(at * 1000 + offset_ms, label)


def base(msg_type: str, label: str, frm: str, at: int = NOW, ttl: int = 30, to: str | None = None,
         version: dict | None = None, **fields) -> dict:
    p = {"dsip": copy.deepcopy(version or F.VERSION), "type": msg_type, "id": uid(label, at), "from": frm}
    if to is not None:
        p["to"] = to
    p.update(fields)
    p["issued_at"] = at
    p["expires_at"] = at + ttl
    return p


def invite(label="inv", frm=None, to=None, at=NOW, **kw) -> dict:
    return base("invite", label, frm or F.did("alice-phone"), at, to=to or F.BOB_WEB,
                intent="interactive", identity={"display_name": "Alice", "claims": []},
                media=copy.deepcopy(MEDIA_OFFER), transports=copy.deepcopy(TRANSPORTS),
                policy={"recording": "consent-required", "ai_processing": "denied"}, **kw)


def session_msg(msg_type: str, label: str, session: str, frm: str, to: str, at: int = NOW, **kw) -> dict:
    return base(msg_type, label, frm, at, to=to, session=session, **kw)


def hello_client(label="hello", frm=None, on_behalf_of=None, at=NOW, **kw) -> dict:
    p = base("hello", label, frm or F.did("bob-phone"), at, version=F.VERSION_TRANSPORT, bindings=["ws/1.0"], **kw)
    if on_behalf_of:
        p["on_behalf_of"] = on_behalf_of
    return p


def hello_relay(in_reply_to: str, label="relay-hello", at=NOW + 1, **caps) -> dict:
    capabilities = {"max_envelope_bytes": 65536, "store_and_forward": True,
                    "rate_limit": {"envelopes_per_minute": 120, "invites_per_minute": 10}}
    capabilities.update(caps)
    return base("hello", label, F.RELAY_WEB, at, version=F.VERSION_TRANSPORT,
                in_reply_to=in_reply_to, capabilities=capabilities)


def signed(payload: dict, signer_name: str, kid: str | None = None, **kw) -> dict:
    k = F.KEYS[signer_name]
    return E.sign(payload, k, kid or k.kid, **kw)


def default_context(**over) -> dict:
    ctx = {"now": NOW, "did_documents": F.did_documents(), "delegations": F.standard_delegations(),
           "seen_ids": [], "supported": F.SUPPORTED}
    ctx.update(over)
    return ctx


def vector(vid: str, kind: str, description: str, spec_ref: list[str], context: dict, inp: dict, expect: dict) -> dict:
    return {"vector": vid, "format": FORMAT_VERSION, "kind": kind, "description": description,
            "spec_ref": spec_ref, "context": context, "input": inp, "expect": expect}


def accept(**extra) -> dict:
    out = {"verdict": "accept"}
    out.update(extra)
    return out


def reject(code: str, reason: str | None = None) -> dict:
    out = {"verdict": "reject", "code": code}
    if reason:
        out["reason"] = reason
    return out
