"""Semantic vectors — stages 12–14 on decoded payloads (schema README checks 5, 7, 9, 11; spec §11, §9.3, §13.2, §14.2, §15, §19.4)."""
from __future__ import annotations

import copy

from .. import fixtures as F
from .common import (NOW, invite, hello_client, hello_relay, session_msg, vector, accept, reject, uid,
                     MEDIA_OFFER, TRANSPORTS, AUDIO_SELECTION, ONE_TRANSPORT)

APH, BPH = F.did("alice-phone"), F.did("bob-phone")


def sv(vid, desc, refs, payload, expect, ctx=None):
    context = {"now": NOW, "supported": F.SUPPORTED}
    context.update(ctx or {})
    return vector(f"semantic/{vid}", "semantic", desc, refs, context, {"payload": payload}, expect)


def vectors() -> list[dict]:
    out = []
    inv = invite()
    sid = inv["id"]

    # --- version negotiation (§11)
    out.append(sv("version-compatible", "core 1.0 / min_core 1.0 / known profile.", ["§11.2"], inv, accept()))
    out.append(sv("version-major-mismatch", "core 2.0 is incompatible by default.", ["§11.2", "§11.3"],
                  {**inv, "dsip": {**F.VERSION, "core": "2.0", "min_core": "2.0"}},
                  reject("version-unsupported", "session.unsupported-core-version")))
    out.append(sv("version-minor-newer-accepted", "core 1.3 with min_core 1.0: minor versions are backward-compatible.", ["§11.2"],
                  {**inv, "dsip": {**F.VERSION, "core": "1.3"}}, accept()))
    out.append(sv("version-min-core-above-ours", "min_core 1.5 exceeds our 1.0 support.", ["§11.2"],
                  {**inv, "dsip": {**F.VERSION, "core": "1.5", "min_core": "1.5"}},
                  reject("version-unsupported", "session.unsupported-core-version")))
    out.append(sv("version-unknown-critical", "Unknown critical extension requires rejection.", ["§11.2", "§11.3"],
                  {**inv, "dsip": {**F.VERSION, "extensions": ["quantum-ring/1.0"], "critical": ["quantum-ring/1.0"]}},
                  reject("version-unsupported", "session.unsupported-critical-extension")))
    out.append(sv("version-unknown-noncritical-ignored", "Unknown non-critical extension may be ignored.", ["§11.2"],
                  {**inv, "dsip": {**F.VERSION, "extensions": ["quantum-ring/1.0"]}}, accept()))
    out.append(sv("version-unknown-profile", "No mutually supported profile version.", ["§11.3"],
                  {**inv, "dsip": {**F.VERSION, "profiles": ["interactive-media/2.0"]}},
                  reject("version-unsupported", "session.unsupported-profile-version")))

    # --- schema dispatch
    out.append(sv("unknown-message-type", "type not in the core message set.", ["§12.1"],
                  {**inv, "type": "transfer"}, reject("unknown-type")))
    out.append(sv("schema-fail-after-version-ok", "Version fine; offerless invite fails schema.", ["§14.2"],
                  {k: v for k, v in inv.items() if k != "media"}, reject("schema-invalid")))

    # --- registry membership with fallback (check 5, §15.1, §14.3, §12.10)
    rej = session_msg("reject", "rej", sid, BPH, APH, NOW + 5, reason="user.declined")
    out.append(sv("reason-registered", "Registered token valid on reject.", ["§15.4"], rej,
                  accept(effective={"reason": "user.declined", "fallback": "none"})))
    out.append(sv("reason-unknown-condition-known-category", "endpoint.on-fire is unregistered; category fallback applies.", ["§15.1", "§15.3"],
                  {**rej, "reason": "endpoint.on-fire"}, accept(effective={"reason": "endpoint.on-fire", "fallback": "category"})))
    out.append(sv("reason-unknown-category", "Unrecognized category → treated as session.failed.", ["§15.1"],
                  {**rej, "reason": "x-contactcenter.queue-full"}, accept(effective={"reason": "session.failed", "fallback": "unknown-category"})))
    out.append(sv("reason-not-valid-on-type", "user.hangup is registered for bye only; on reject it is accepted with a warning (Impl, spec-gap 10).",
                  ["§15.4"], {**rej, "reason": "user.hangup"},
                  accept(effective={"reason": "user.hangup", "fallback": "none"}, warnings=["reason-not-valid-on-type"])))
    bye = session_msg("bye", "bye", sid, APH, BPH, NOW + 300, reason="user.hangup")
    out.append(sv("bye-reason-registered", "user.hangup on bye.", ["§15.4"], bye, accept(effective={"reason": "user.hangup", "fallback": "none"})))
    ans = session_msg("answer", "ans", sid, BPH, APH, NOW + 5, answered_by="butler", media=AUDIO_SELECTION, transports=ONE_TRANSPORT)
    out.append(sv("answered-by-unknown-renders-service", "Unknown answered_by MUST be treated as service.", ["§14.3"],
                  ans, accept(effective={"answered_by": "service"})))
    out.append(sv("answered-by-gateway", "Registered answered_by gateway.", ["§14.3"],
                  {**ans, "answered_by": "gateway"}, accept(effective={"answered_by": "gateway"})))
    prog = session_msg("progress", "prog", sid, BPH, APH, NOW + 1, status="pondering")
    out.append(sv("progress-unknown-status-is-trying", "Unknown progress status is treated as trying.", ["§12.10"],
                  prog, accept(effective={"status": "trying"})))
    out.append(sv("progress-forwarded", "Registered status forwarded.", ["§12.10"],
                  {**prog, "status": "forwarded"}, accept(effective={"status": "forwarded"})))
    err = {"dsip": F.VERSION_TRANSPORT, "type": "error", "id": uid("err"), "from": F.RELAY_WEB, "to": APH,
           "reason": "transport.hello-required", "issued_at": NOW, "expires_at": NOW + 30}
    out.append(sv("error-reason-registered", "transport.hello-required on error.", ["§15.4"], err,
                  accept(effective={"reason": "transport.hello-required", "fallback": "none"})))

    # --- anti-splicing (check 7)
    hc = hello_client(on_behalf_of=F.BOB_WEB)
    hr = hello_relay(hc["id"])
    out.append(sv("hello-in-reply-to-matches", "Relay hello echoes the id the client actually sent.", ["§13.2", "§20.5"],
                  hr, accept(), ctx={"sent_hello_id": hc["id"]}))
    out.append(sv("hello-in-reply-to-spliced", "Relay hello captured from another connection: in_reply_to mismatch → close.", ["§13.2", "§20.5"],
                  hr, reject("hello-in-reply-to-mismatch"), ctx={"sent_hello_id": uid("other-hello")}))

    # --- selection subset (check 9, §14.2)
    offer = {"media": copy.deepcopy(MEDIA_OFFER), "transports": copy.deepcopy(TRANSPORTS)}
    good_ans = session_msg("answer", "ans2", sid, BPH, APH, NOW + 5, answered_by="user",
                           media=[{"type": "audio", "direction": "sendrecv", "codecs": [{"id": "codec:audio/opus"}]},
                                  {"type": "video", "direction": "recvonly", "codecs": [{"id": "codec:video/h264"}]}],
                           transports=ONE_TRANSPORT)
    out.append(sv("selection-subset-ok", "Answer selects opus audio and recvonly h264 video from the offer.", ["§14.2"],
                  good_ans, accept(effective={"answered_by": "user"}), ctx={"offer": offer}))
    out.append(sv("selection-codec-not-offered", "Answer selects a codec the offer did not contain.", ["§14.2"],
                  {**good_ans, "media": [{"type": "audio", "direction": "sendrecv", "codecs": [{"id": "codec:audio/aac"}]}]},
                  reject("selection-not-subset"), ctx={"offer": offer}))
    out.append(sv("selection-transport-not-offered", "Answer selects a transport the offer did not contain.", ["§14.2"],
                  {**good_ans, "transports": [{"id": "transport:quic-media"}]}, reject("selection-not-subset"), ctx={"offer": offer}))
    out.append(sv("selection-media-type-not-offered", "Answer selects text media absent from the offer.", ["§14.2"],
                  {**good_ans, "media": [{"type": "text", "direction": "sendrecv", "codecs": [{"id": "codec:text/t140"}]}]},
                  reject("selection-not-subset"), ctx={"offer": offer}))
    sendonly_offer = {"media": [{"type": "audio", "direction": "sendonly", "codecs": [{"id": "codec:audio/opus"}]}],
                      "transports": ONE_TRANSPORT}
    out.append(sv("selection-direction-incompatible", "Offer was sendonly; answer sendrecv is not a valid direction answer (Impl, spec-gap 9).",
                  ["§14.2"], {**good_ans, "media": [{"type": "audio", "direction": "sendrecv", "codecs": [{"id": "codec:audio/opus"}]}]},
                  reject("selection-not-subset"), ctx={"offer": sendonly_offer}))
    out.append(sv("selection-direction-recvonly-answers-sendonly", "Offer sendonly; answer recvonly is valid.", ["§14.2"],
                  {**good_ans, "media": [{"type": "audio", "direction": "recvonly", "codecs": [{"id": "codec:audio/opus"}]}]},
                  accept(effective={"answered_by": "user"}), ctx={"offer": sendonly_offer}))
    out.append(sv("selection-no-offer-context", "Without an offer in context the subset check is skipped.", ["§14.2"],
                  good_ans, accept(effective={"answered_by": "user"})))

    # --- subscription caps (§9.3, check 11)
    sub = {"dsip": F.VERSION, "type": "subscribe", "id": uid("sub"), "from": APH, "to": "did:web:example.com", "target": F.BOB_WEB,
           "events": ["presence"], "expires_in": 3600, "issued_at": NOW, "expires_at": NOW + 30}
    out.append(sv("subscribe-presence-at-cap", "Presence subscription at exactly 3,600 s.", ["§9.3"], sub, accept()))
    out.append(sv("subscribe-presence-over-cap", "Presence subscription of 3,601 s exceeds the hard cap.", ["§9.3"],
                  {**sub, "expires_in": 3601}, reject("subscription-lifetime-exceeded", "policy.subscription-lifetime")))
    out.append(sv("subscribe-publication-long-ok", "Publication subscription of 86,400 s is within its cap.", ["§9.3"],
                  {**sub, "events": ["publication"], "expires_in": 86400}, accept()))
    out.append(sv("subscribe-mixed-events-presence-cap-applies", "Mixed events: the tighter presence cap applies.", ["§9.3"],
                  {**sub, "events": ["publication", "presence"], "expires_in": 7200}, reject("subscription-lifetime-exceeded", "policy.subscription-lifetime")))

    # --- key rotation (§7.5, v0.7, spec-gap 22)
    k1, k2 = F.web_kid(F.BOB_WEB), f"{F.BOB_WEB}#key-2"
    rot = {"dsip": F.VERSION, "type": "key-rotation", "id": uid("rot"), "from": F.BOB_WEB, "subject": F.BOB_WEB,
           "previous": k1, "next": k2, "next_public_key_multibase": F.multibase_pub("bob-next"), "reason": "scheduled",
           "devices": [F.did("bob-phone")], "issued_at": NOW, "expires_at": NOW + 86400}
    out.append(sv("key-rotation-signed-by-previous", "The retiring key signs its own rotation record.", ["§7.5"], rot, accept(), ctx={"signer_kid": k1}))
    out.append(sv("key-rotation-signer-not-previous", "Signed by some other method of the subject without recovery: not a rotation by the retiring key.", ["§7.5"],
                  rot, reject("rotation-signer-not-previous"), ctx={"signer_kid": f"{F.BOB_WEB}#key-9"}))
    out.append(sv("key-rotation-recovery-signer", "recovery: true lets a recovery key of the subject sign when previous is lost.", ["§7.5", "§7.6"],
                  {**rot, "recovery": True, "reason": "lost"}, accept(), ctx={"signer_kid": f"{F.BOB_WEB}#recovery-1"}))
    out.append(sv("key-rotation-next-same-as-previous", "next MUST differ from previous.", ["§7.5"], {**rot, "next": k1},
                  reject("rotation-next-same-as-previous"), ctx={"signer_kid": k1}))
    out.append(sv("key-rotation-subject-mismatch", "from MUST be the subject: only the identity rotates its own keys.", ["§7.5"],
                  {**rot, "from": F.did("alice")}, reject("rotation-subject-mismatch"), ctx={"signer_kid": k1}))
    ntf = {"dsip": F.VERSION, "type": "notify", "id": uid("ntf"), "from": "did:web:example.com", "to": APH, "subscription": sub["id"],
           "seq": 3, "state": "terminated", "reason": "session.expired", "body": {}, "issued_at": NOW + 1, "expires_at": NOW + 31}
    out.append(sv("notify-terminated-reason", "Terminal notify reason resolves through the registry.", ["§9.3"], ntf,
                  accept(effective={"reason": "session.expired", "fallback": "none"})))

    # --- first contact (§19.4)
    intro_id = uid("intro")
    grant = {"dsip": F.VERSION, "type": "grant", "id": uid("grant"), "session": intro_id, "from": F.BOB_WEB, "to": F.did("carol-phone"),
             "scope": ["dsip.invite"], "valid_until": NOW + 31536000, "issued_at": NOW + 600, "expires_at": NOW + 630}
    out.append(sv("grant-references-known-introduction", "Grant session matches a pending introduction.", ["§19.4"],
                  grant, accept(), ctx={"known_introductions": [intro_id]}))
    out.append(sv("grant-references-unknown-introduction", "Grant session references no pending introduction.", ["§19.4"],
                  grant, reject("grant-unknown-introduction"), ctx={"known_introductions": [uid("some-other")]}))
    intro = {"dsip": F.VERSION, "type": "introduction", "id": intro_id, "from": F.did("carol-phone"), "to": F.BOB_WEB,
             "identity": {"display_name": "Carol Nguyen", "claims": []}, "purpose": "Hello.", "issued_at": NOW, "expires_at": NOW + 604800}
    out.append(sv("introduction-size-from-context", "Encoded size supplied by context exceeds 4,096.", ["§19.4"],
                  intro, reject("introduction-too-large"), ctx={"encoded_size": 4097}))
    out.append(sv("introduction-size-at-cap", "Encoded size exactly 4,096 is allowed.", ["§19.4"],
                  intro, accept(), ctx={"encoded_size": 4096}))
    return out
