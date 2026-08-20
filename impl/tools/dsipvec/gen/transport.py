"""Transport vectors — ws/1.0 binding (spec §13.2, §20.5; schema README checks 7, 8)."""
from __future__ import annotations

import json

from .. import fixtures as F
from .. import envelope as E
from .common import NOW, invite, hello_client, hello_relay, signed, default_context, vector, accept, reject, session_msg

APH, BPH = F.did("alice-phone"), F.did("bob-phone")


def tv(vid, desc, refs, env, expect, ctx=None, frame=None):
    inp = {"envelope": env}
    if frame is not None:
        inp["frame"] = frame
    return vector(f"transport/{vid}", "transport", desc, refs, ctx or default_context(), inp, expect)


def vectors() -> list[dict]:
    out = []
    hc = hello_client(on_behalf_of=F.BOB_WEB)
    hc_env = signed(hc, "bob-phone")
    hr_env = signed(hello_relay(hc["id"]), "relay", kid=F.web_kid(F.RELAY_WEB))

    out.append(tv("client-hello", "First envelope on a connection: client hello, device key, on_behalf_of delegation verified.",
                  ["§13.2"], hc_env, accept(type="hello", signer=BPH, identity=F.BOB_WEB)))
    out.append(tv("relay-hello-bound", "Relay hello whose in_reply_to matches the client hello id that was sent.", ["§13.2", "§20.5"],
                  hr_env, accept(type="hello", signer=F.RELAY_WEB, identity=F.RELAY_WEB), ctx=default_context(sent_hello_id=hc["id"])))
    spliced = signed(hello_relay(hello_client("other-client", frm=F.did("alice-phone"))["id"]), "relay", kid=F.web_kid(F.RELAY_WEB))
    out.append(tv("relay-hello-spliced", "Valid signed relay hello replayed from another connection: in_reply_to mismatch.", ["§13.2", "§20.5"],
                  spliced, reject("hello-in-reply-to-mismatch"), ctx=default_context(sent_hello_id=hc["id"])))
    out.append(tv("relay-hello-capabilities-wrong-constant", "Relay hello advertising max_envelope_bytes ≠ 65536.", ["§13.2"],
                  signed(hello_relay(hc["id"], max_envelope_bytes=32768), "relay", kid=F.web_kid(F.RELAY_WEB)),
                  reject("schema-invalid"), ctx=default_context(sent_hello_id=hc["id"])))
    out.append(tv("relay-hello-unknown-capability-ignored", "Unknown capability fields are ignored.", ["§13.2"],
                  signed(hello_relay(hc["id"], x_future_cap=True), "relay", kid=F.web_kid(F.RELAY_WEB)),
                  accept(type="hello", signer=F.RELAY_WEB, identity=F.RELAY_WEB), ctx=default_context(sent_hello_id=hc["id"])))

    # size cap
    inv = invite()
    small_env = signed(inv, "alice-phone")
    out.append(tv("frame-within-cap", "Ordinary invite frame, well under 65,536 bytes.", ["§13.2"],
                  small_env, accept(type="invite", signer=APH, identity=APH), frame=E.frame(small_env)))
    big = {**inv, "identity": {"display_name": "Alice", "claims": [{"blob": "x" * 70000}]}}
    big_env = signed(big, "alice-phone")
    out.append(tv("frame-over-cap", "Envelope whose text frame exceeds 65,536 bytes must be rejected before any other processing.",
                  ["§13.2"], big_env, reject("frame-too-large", "transport.envelope-too-large"), frame=E.frame(big_env)))
    # exactly at the cap: pad the display name until the frame is 65,536 bytes
    pad_len = 65536 - len(E.frame(signed({**inv, "identity": {"display_name": "Alice", "claims": [{"pad": ""}]}}, "alice-phone")))
    # base64 expands 3→4 bytes; find a payload padding that lands exactly on the cap
    exact_env = None
    for n in range(max(0, pad_len * 3 // 4 - 8), pad_len * 3 // 4 + 8):
        cand = signed({**inv, "identity": {"display_name": "Alice", "claims": [{"pad": "a" * n}]}}, "alice-phone")
        if len(E.frame(cand)) == 65536:
            exact_env = cand
            break
    if exact_env is not None:
        out.append(tv("frame-exactly-at-cap", "A 65,536-byte frame is allowed (limit is inclusive).", ["§13.2"],
                      exact_env, accept(type="invite", signer=APH, identity=APH), frame=E.frame(exact_env)))

    # session traffic before hello
    out.append(tv("session-traffic-before-hello", "An invite arriving on a connection with no verified hello → transport.hello-required.",
                  ["§13.2"], small_env, reject("hello-required", "transport.hello-required"), ctx=default_context(hello_verified=False)))
    out.append(tv("session-traffic-after-hello", "Same invite after hello is verified.", ["§13.2"],
                  small_env, accept(type="invite", signer=APH, identity=APH), ctx=default_context(hello_verified=True)))
    out.append(tv("hello-itself-needs-no-prior-hello", "A hello is the one message permitted before binding.", ["§13.2"],
                  hc_env, accept(type="hello", signer=BPH, identity=F.BOB_WEB), ctx=default_context(hello_verified=False)))

    # hello replay
    out.append(tv("hello-replayed-duplicate-id", "Re-sent hello with an id already seen is a replay.", ["§13.2", "§12.9"],
                  hc_env, reject("duplicate-id"), ctx=default_context(seen_ids=[hc["id"]])))
    stale = hello_client("stale", on_behalf_of=F.BOB_WEB, at=NOW - 600, ttl=3600)
    out.append(tv("hello-stale-issued-at", "hello is subject to the replay window.", ["§13.2", "§12.9"],
                  signed(stale, "bob-phone"), reject("replay-window")))
    return out
