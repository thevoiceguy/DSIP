#!/usr/bin/env python3
"""Sanity harness: validates sample payloads against the generated schemas.
Positive samples MUST pass; negative samples MUST fail for the stated reason."""
import json, sys
from pathlib import Path
from jsonschema import Draft202012Validator

SCHEMA_DIR = Path(__file__).parent / "schemas"

def load(name):
    return json.loads((SCHEMA_DIR / f"{name}.schema.json").read_text())

V = "1.0"
DSIP = {"core": V, "min_core": V, "profiles": ["interactive-media/1.0"], "extensions": [], "critical": []}
U = {  # real ULIDs (26-char Crockford base32)
    "inv":  "01J5Y0Q6K8ZJ4M2N7P9R3S5T7V",
    "prog": "01J5Y0Q7A1BCD2EF3GH4JK5MN6",
    "ans":  "01J5Y0Q8P0QRS1TV2WX3YZ4A5B",
    "can":  "01J5Y0Q9C6DE7FG8HJ9KM0NP1Q",
    "upd":  "01J5Y0QAR2ST3VW4XY5Z6A7B8C",
    "hel":  "01J5Y0QBD8EF9GH0JK1MN2PQ3R",
    "rhel": "01J5Y0QCS4TV5WX6YZ7A8B9C0D",
}
ALICE, ALICE_DEV = "did:key:z6MkAliceController", "did:key:z6MkAlicePhone"
BOB, BOB_DEV = "did:web:example.com:users:bob", "did:key:z6MkBobLaptop"
NOW = 1760000000

MEDIA_OFFER = [{"type": "audio", "direction": "sendrecv",
                "codecs": [{"id": "codec:audio/opus", "sample_rates": [48000], "channels": [1, 2]}]}]
TRANSPORTS = [{"id": "transport:webrtc", "ice": "trickle"}]

cases = []  # (schema, instance, should_pass, label)

cases.append(("invite", {
    "dsip": DSIP, "type": "invite", "id": U["inv"], "from": ALICE_DEV, "to": BOB,
    "issued_at": NOW, "expires_at": NOW + 30, "intent": "interactive",
    "identity": {"display_name": "Alice", "claims": []},
    "media": MEDIA_OFFER, "transports": TRANSPORTS,
    "policy": {"recording": "consent-required", "ai_processing": "denied"},
}, True, "valid invite"))

cases.append(("invite", {
    "dsip": DSIP, "type": "invite", "id": U["inv"], "from": ALICE_DEV, "to": BOB,
    "issued_at": NOW, "expires_at": NOW + 30, "transports": TRANSPORTS,
}, False, "offerless invite (media.offer-required)"))

cases.append(("invite", {
    "dsip": DSIP, "type": "invite", "id": "01HZINVITEABC", "from": ALICE_DEV, "to": BOB,
    "issued_at": NOW, "expires_at": NOW + 30, "media": MEDIA_OFFER, "transports": TRANSPORTS,
}, False, "spec-prose illustrative id is not a valid ULID"))

cases.append(("progress", {
    "dsip": DSIP, "type": "progress", "id": U["prog"], "session": U["inv"],
    "from": BOB_DEV, "to": ALICE_DEV, "status": "ringing", "ring_timeout": 120,
    "issued_at": NOW + 1, "expires_at": NOW + 31,
}, True, "valid ringing progress"))

cases.append(("progress", {
    "dsip": DSIP, "type": "progress", "id": U["prog"], "session": U["inv"],
    "from": BOB_DEV, "to": ALICE_DEV, "status": "queued", "queue_timeout": 600,
    "issued_at": NOW + 1, "expires_at": NOW + 31,
}, True, "valid queued progress with queue_timeout"))

cases.append(("progress", {
    "dsip": DSIP, "type": "progress", "id": U["prog"], "session": U["inv"],
    "from": BOB_DEV, "to": ALICE_DEV, "status": "queued",
    "issued_at": NOW + 1, "expires_at": NOW + 31,
}, False, "queued progress missing queue_timeout"))

cases.append(("progress", {
    "dsip": DSIP, "type": "progress", "id": U["prog"], "session": U["inv"],
    "from": BOB_DEV, "to": ALICE_DEV, "status": "queued", "queue_timeout": 3600,
    "issued_at": NOW + 1, "expires_at": NOW + 31,
}, False, "queue_timeout exceeds 1800s core cap"))

cases.append(("answer", {
    "dsip": DSIP, "type": "answer", "id": U["ans"], "session": U["inv"],
    "from": BOB_DEV, "to": ALICE_DEV, "answered_by": "screening",
    "media": [{"type": "audio", "direction": "recvonly", "codecs": [{"id": "codec:audio/opus"}]}],
    "transports": [{"id": "transport:webrtc"}],
    "issued_at": NOW + 5, "expires_at": NOW + 35,
}, True, "valid screening answer with constrained media"))

cases.append(("answer", {
    "dsip": DSIP, "type": "answer", "id": U["ans"], "session": U["inv"],
    "from": BOB_DEV, "to": ALICE_DEV,
    "media": MEDIA_OFFER, "transports": [{"id": "transport:webrtc"}],
    "issued_at": NOW + 5, "expires_at": NOW + 35,
}, False, "answer missing required answered_by"))

cases.append(("cancel", {
    "dsip": DSIP, "type": "cancel", "id": U["can"], "session": U["inv"],
    "from": ALICE_DEV, "to": BOB, "reason": "session.answered-elsewhere",
    "issued_at": NOW + 6, "expires_at": NOW + 36,
}, True, "valid per-leg cancel, namespaced reason"))

cases.append(("cancel", {
    "dsip": DSIP, "type": "cancel", "id": U["can"], "session": U["inv"],
    "from": ALICE_DEV, "to": BOB, "reason": "timeout",
    "issued_at": NOW + 6, "expires_at": NOW + 36,
}, False, "legacy flat reason token rejected (must be category.condition)"))

cases.append(("update", {
    "dsip": DSIP, "type": "update", "id": U["upd"], "session": U["inv"],
    "from": BOB_DEV, "to": ALICE_DEV, "answered_by": "user",
    "media": [{"type": "video", "direction": "sendrecv", "codecs": [{"id": "codec:video/h264", "profiles": ["baseline"]}]}],
    "issued_at": NOW + 60, "expires_at": NOW + 90,
}, True, "valid escalation update (screening -> user)"))

cases.append(("hello", {
    "dsip": {**DSIP, "profiles": []}, "type": "hello", "id": U["hel"],
    "from": BOB_DEV, "on_behalf_of": BOB, "bindings": ["ws/1.0"],
    "issued_at": NOW, "expires_at": NOW + 30,
}, True, "valid client hello"))

cases.append(("hello", {
    "dsip": {**DSIP, "profiles": []}, "type": "hello", "id": U["rhel"],
    "from": "did:web:relay.example.com", "in_reply_to": U["hel"],
    "capabilities": {"max_envelope_bytes": 65536, "store_and_forward": True,
                     "rate_limit": {"envelopes_per_minute": 120, "invites_per_minute": 10},
                     "push_wake": ["apns", "fcm"]},
    "issued_at": NOW + 1, "expires_at": NOW + 31,
}, True, "valid relay hello with echo + capabilities"))

cases.append(("hello", {
    "dsip": {**DSIP, "profiles": []}, "type": "hello", "id": U["rhel"],
    "from": "did:web:relay.example.com", "in_reply_to": U["hel"],
    "issued_at": NOW + 1, "expires_at": NOW + 31,
}, False, "relay hello with in_reply_to but no capabilities"))

cases.append(("hello", {
    "dsip": {**DSIP, "profiles": []}, "type": "hello", "id": U["rhel"],
    "from": "did:web:relay.example.com", "in_reply_to": U["hel"],
    "capabilities": {"max_envelope_bytes": 32768},
    "issued_at": NOW + 1, "expires_at": NOW + 31,
}, False, "capabilities with wrong max_envelope_bytes (binding constant is 65536)"))

cases.append(("bye", {
    "dsip": DSIP, "type": "bye", "id": U["upd"], "session": U["inv"],
    "from": ALICE_DEV, "to": BOB_DEV, "reason": "user.hangup",
    "issued_at": NOW + 300, "expires_at": NOW + 330,
}, True, "valid bye"))

cases.append(("error", {
    "dsip": {**DSIP, "profiles": []}, "type": "error", "id": U["prog"],
    "from": "did:web:relay.example.com", "to": ALICE_DEV,
    "reason": "transport.rate-limited", "retry_after": 30,
    "in_reply_to": U["inv"],
    "issued_at": NOW, "expires_at": NOW + 30,
}, True, "valid transport-scoped error, no session field"))

cases.append(("publish", {
    "dsip": {"core": V, "min_core": V, "profiles": ["verified-broadcast/1.0"],
             "extensions": ["broadcast-provenance/1.0"], "critical": []},
    "type": "publish", "id": U["inv"], "from": "did:web:wxyz.com",
    "publisher": "did:web:wxyz.com", "stream_id": "did:web:wxyz.com:radio:main",
    "title": "WXYZ Live Radio", "state": "live",
    "variants": [{"id": "main-opus", "media": ["audio"], "codec": "codec:audio/opus",
                  "transport": "transport:webrtc", "uri": "wss://live.wxyz.com/dsip/webrtc/main"}],
    "policy": {"redistribution": "allowed-with-attribution"},
    "issued_at": NOW, "expires_at": NOW + 300,
}, True, "valid broadcast publication"))


cases.append(("info", {
    "dsip": DSIP, "type": "info", "id": U["upd"], "session": U["inv"],
    "from": BOB_DEV, "to": ALICE_DEV, "about": "transport:webrtc",
    "data": {"candidates": [{"candidate": "candidate:842163049 1 udp 1677729535 203.0.113.7 61481 typ srflx",
                             "sdp_mid": "0", "sdp_m_line_index": 0}],
             "end_of_candidates": False},
    "issued_at": NOW + 6, "expires_at": NOW + 36,
}, True, "valid info carrying trickle ICE candidates"))

cases.append(("info", {
    "dsip": DSIP, "type": "info", "id": U["upd"], "session": U["inv"],
    "from": BOB_DEV, "to": ALICE_DEV, "about": "transport:webrtc",
    "issued_at": NOW + 6, "expires_at": NOW + 36,
}, False, "info missing required data object"))

cases.append(("introduction", {
    "dsip": DSIP, "type": "introduction", "id": U["hel"],
    "from": "did:key:z6MkCarolPhone", "to": BOB,
    "identity": {"display_name": "Carol Nguyen", "claims": []},
    "purpose": "We met at the mesh-networking meetup; following up about the antenna group buy.",
    "issued_at": NOW, "expires_at": NOW + 604800,
}, True, "valid introduction"))

cases.append(("introduction", {
    "dsip": DSIP, "type": "introduction", "id": U["hel"],
    "from": "did:key:z6MkCarolPhone", "to": BOB,
    "identity": {"display_name": "Carol Nguyen", "claims": []},
    "purpose": "x" * 300,
    "issued_at": NOW, "expires_at": NOW + 604800,
}, False, "introduction purpose exceeds 280 chars"))

cases.append(("grant", {
    "dsip": DSIP, "type": "grant", "id": U["rhel"], "session": U["hel"],
    "from": BOB, "to": "did:key:z6MkCarolPhone",
    "scope": ["dsip.invite"], "valid_until": NOW + 31536000,
    "issued_at": NOW + 600, "expires_at": NOW + 630,
}, True, "valid contact grant referencing the introduction"))

cases.append(("grant", {
    "dsip": DSIP, "type": "grant", "id": U["rhel"], "session": U["hel"],
    "from": BOB, "to": "did:key:z6MkCarolPhone",
    "scope": ["invite"], "valid_until": NOW + 31536000,
    "issued_at": NOW + 600, "expires_at": NOW + 630,
}, False, "grant scope missing dsip. prefix"))

cases.append(("subscribe", {
    "dsip": DSIP, "type": "subscribe", "id": U["prog"],
    "from": ALICE_DEV, "to": "did:web:example.com",
    "target": BOB, "events": ["presence"], "expires_in": 600,
    "issued_at": NOW, "expires_at": NOW + 30,
}, True, "valid presence subscription"))

cases.append(("subscribe", {
    "dsip": DSIP, "type": "subscribe", "id": U["prog"],
    "from": ALICE_DEV, "to": "did:web:example.com",
    "target": BOB, "events": ["presence"], "expires_in": 100000,
    "issued_at": NOW, "expires_at": NOW + 30,
}, False, "expires_in exceeds 86400 schema ceiling"))

cases.append(("notify", {
    "dsip": DSIP, "type": "notify", "id": U["ans"],
    "from": "did:web:example.com", "to": ALICE_DEV,
    "subscription": U["prog"], "seq": 1, "state": "active",
    "body": {"type": "presence", "state": "available", "audience": "contacts-only"},
    "issued_at": NOW + 1, "expires_at": NOW + 31,
}, True, "valid initial notify with current state"))

cases.append(("notify", {
    "dsip": DSIP, "type": "notify", "id": U["ans"],
    "from": "did:web:example.com", "to": ALICE_DEV,
    "subscription": U["prog"], "seq": 9, "state": "terminated",
    "reason": "policy.terminated", "body": {},
    "issued_at": NOW + 700, "expires_at": NOW + 730,
}, True, "valid terminal notify with reason"))


# ---- v0.7 additions: provenance, key-rotation, reachability-hint, webrtc info.data, publish.integrity
BCAST = {"core": V, "min_core": V, "profiles": ["verified-broadcast/1.0"], "extensions": [], "critical": []}
PUB_ID = "01J5Y0QEPXB00AAAAAAAAAAAAB"
cases.append(("provenance", {
    "dsip": BCAST, "type": "provenance", "id": "01J5Y0QFPRV00AAAAAAAAAAAAC", "from": "did:web:cdn.example",
    "original_stream": "did:web:wxyz.com:radio:main", "original_publication": PUB_ID, "processor": "did:web:cdn.example",
    "operation": "transcode", "input_variant": "main-opus-low-latency", "output_variant": "main-aac-hls",
    "output_uri": "https://cdn.example/wxyz/main.m3u8", "issued_at": NOW + 100, "expires_at": NOW + 3700,
}, True, "valid provenance statement"))
cases.append(("provenance", {
    "dsip": BCAST, "type": "provenance", "id": "01J5Y0QFPRV00AAAAAAAAAAAAC", "from": "did:web:cdn.example",
    "original_stream": "did:web:wxyz.com:radio:main", "original_publication": PUB_ID, "processor": "did:web:cdn.example",
    "operation": "transcode", "input_variant": "main-opus-low-latency", "issued_at": NOW + 100, "expires_at": NOW + 3700,
}, False, "provenance without output_variant"))
cases.append(("publish", {
    "dsip": BCAST, "type": "publish", "id": PUB_ID, "from": "did:web:wxyz.com", "publisher": "did:web:wxyz.com",
    "stream_id": "did:web:wxyz.com:radio:main", "state": "live", "integrity": "derivative-bound",
    "variants": [{"id": "main-opus", "media": ["audio"], "codec": "codec:audio/opus", "transport": "transport:webrtc", "uri": "wss://live.wxyz.com/dsip/webrtc/main"}],
    "issued_at": NOW, "expires_at": NOW + 300,
}, True, "publish with record-level integrity"))
cases.append(("publish", {
    "dsip": BCAST, "type": "publish", "id": PUB_ID, "from": "did:web:wxyz.com", "publisher": "did:web:wxyz.com",
    "stream_id": "did:web:wxyz.com:radio:main", "state": "live", "integrity": "Metadata Only",
    "variants": [{"id": "main-opus", "media": ["audio"], "codec": "codec:audio/opus", "transport": "transport:webrtc", "uri": "wss://live.wxyz.com/dsip/webrtc/main"}],
    "issued_at": NOW, "expires_at": NOW + 300,
}, False, "publish integrity must be a token"))
ROT = {"dsip": DSIP, "type": "key-rotation", "id": "01J5Y0QJR0T00AAAAAAAAAAAAF", "from": BOB, "subject": BOB,
       "previous": BOB + "#key-1", "next": BOB + "#key-2", "next_public_key_multibase": "z6MkrgXgMcSfqUQ6bhMEL1dhqvPYU4YaueY56Mw8aee9YN4R",
       "reason": "scheduled", "devices": [BOB_DEV], "issued_at": NOW, "expires_at": NOW + 86400}
cases.append(("key-rotation", ROT, True, "valid key rotation record"))
cases.append(("key-rotation", {k: v for k, v in ROT.items() if k != "next_public_key_multibase"}, False, "rotation without the next public key"))
cases.append(("key-rotation", {**ROT, "reason": "Scheduled!"}, False, "rotation reason must be a token"))
cases.append(("reachability-hint", {
    "dsip": DSIP, "type": "reachability-hint", "id": "01J5Y0QKHNT00AAAAAAAAAAAAG", "from": ALICE_DEV, "subject": ALICE,
    "endpoints": [{"uri": "wss://relay.example.com/dsip", "bindings": ["ws/1.0"]}], "seq": 3,
    "issued_at": NOW, "expires_at": NOW + 3600,
}, True, "valid reachability hint"))
cases.append(("webrtc-info-data", {"candidates": [{"candidate": "candidate:1 1 udp 2130706431 192.0.2.1 5000 typ host", "sdp_mid": "0", "sdp_m_line_index": 0}],
                                   "end_of_candidates": False}, True, "trickle batch"))
cases.append(("webrtc-info-data", {"candidates": [], "end_of_candidates": True}, True, "end-of-candidates only"))
cases.append(("webrtc-info-data", {"candidates": [{"candidate": "candidate:1 1 udp 2130706431 192.0.2.1 5000 typ host"}], "end_of_candidates": False},
              False, "candidate without sdp_mid"))

def run():
    validators, failures = {}, 0
    for name in {c[0] for c in cases}:
        validators[name] = Draft202012Validator(load(name))
    for schema, instance, should_pass, label in cases:
        errors = list(validators[schema].iter_errors(instance))
        ok = (not errors) == should_pass
        status = "PASS" if ok else "FAIL"
        if not ok:
            failures += 1
        expected = "valid" if should_pass else "invalid"
        print(f"[{status}] {schema:8s} expected-{expected:7s} :: {label}")
        if not ok and errors:
            print(f"         first error: {errors[0].message[:110]}")
    print(f"\n{len(cases)} cases, {failures} failures")
    return failures

if __name__ == "__main__":
    sys.exit(1 if run() else 0)
