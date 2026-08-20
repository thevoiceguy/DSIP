"""Payload (schema) vectors — every schema gets ≥1 accept and ≥1 reject (spec §10.3; schema README)."""
from __future__ import annotations

import copy

from .. import fixtures as F
from .common import (NOW, invite, hello_client, hello_relay, session_msg, vector, accept, reject, uid,
                     MEDIA_OFFER, AUDIO_SELECTION, ONE_TRANSPORT)

APH, BPH = F.did("alice-phone"), F.did("bob-phone")
V = F.VERSION
BCAST_V = {"core": "1.0", "min_core": "1.0", "profiles": ["verified-broadcast/1.0"],
           "extensions": ["broadcast-provenance/1.0"], "critical": []}


def pv(vid, schema, desc, refs, payload, ok=True):
    return vector(f"payload/{vid}", "payload", desc, refs, {}, {"schema": schema, "payload": payload},
                  accept() if ok else reject("schema-invalid"))


def vectors() -> list[dict]:
    out = []
    inv = invite()
    sid = inv["id"]

    # invite
    out.append(pv("invite-valid", "invite", "Complete invite with media offer, transports, identity, policy.", ["§12.1", "§14.2"], inv))
    out.append(pv("invite-offerless", "invite", "Invite without media: schema rejects (media.offer-required at the semantic layer).",
                  ["§14.2"], {k: v for k, v in inv.items() if k != "media"}, ok=False))
    out.append(pv("invite-no-transports", "invite", "Invite without transports.", ["§14.2"],
                  {k: v for k, v in inv.items() if k != "transports"}, ok=False))
    out.append(pv("invite-codec-bare-string", "invite", "Codec entries must be objects, not bare strings (resolves §15.3 vs §16.2).",
                  ["§16.2"], {**inv, "media": [{"type": "audio", "direction": "sendrecv", "codecs": ["codec:audio/opus"]}]}, ok=False))
    out.append(pv("invite-bad-direction", "invite", "Unknown media direction.", ["§16.2"],
                  {**inv, "media": [{"type": "audio", "direction": "both", "codecs": [{"id": "codec:audio/opus"}]}]}, ok=False))
    out.append(pv("invite-float-timestamp", "invite", "Non-integral timestamp fails the integer type. (Integral floats like 1760000000.0 "
                  "satisfy JSON Schema's `integer`; they are caught at parse — see envelope/payload-float-timestamp.)", ["§10.3"],
                  {**inv, "issued_at": NOW + 0.5}, ok=False))
    out.append(pv("invite-version-block-missing-critical", "invite", "Version block without critical array.", ["§11.1"],
                  {**inv, "dsip": {k: v for k, v in V.items() if k != "critical"}}, ok=False))
    out.append(pv("invite-unknown-top-level-field", "invite", "Unknown top-level field: invite schema is closed.", ["§10.3"],
                  {**inv, "surprise": True}, ok=False))
    out.append(pv("invite-policy-bad-value", "invite", "Policy value with uppercase fails the registered-token shape.", ["§16.4"],
                  {**inv, "policy": {"recording": "Consent-Required"}}, ok=False))
    out.append(pv("invite-with-grant-ref", "invite", "Invite referencing a contact grant id.", ["§19.4"],
                  {**inv, "grant": uid("grant")}))
    out.append(pv("invite-accessibility-purpose", "invite", "Media descriptor with a registered purpose (sign-language).", ["§21.3"],
                  {**inv, "media": MEDIA_OFFER + [{"type": "video", "purpose": "sign-language", "direction": "sendrecv",
                                                    "codecs": [{"id": "codec:video/av1"}]}]}))

    # progress
    prog = session_msg("progress", "prog", sid, BPH, APH, NOW + 1, status="ringing", ring_timeout=120)
    out.append(pv("progress-ringing", "progress", "Ringing progress with ring_timeout.", ["§12.10"], prog))
    out.append(pv("progress-queued-valid", "progress", "Queued progress with queue_timeout.", ["§12.10"],
                  {**prog, "status": "queued", "queue_timeout": 600}))
    out.append(pv("progress-queued-missing-timeout", "progress", "queued REQUIRES queue_timeout.", ["§12.10"],
                  {**prog, "status": "queued"}, ok=False))
    out.append(pv("progress-queue-timeout-over-cap", "progress", "queue_timeout above the 1800 s core cap.", ["§12.10", "§12.9"],
                  {**prog, "status": "queued", "queue_timeout": 3600}, ok=False))
    out.append(pv("progress-ring-timeout-below-bound", "progress", "ring_timeout below the 30 s lower bound.", ["§12.9"],
                  {**prog, "ring_timeout": 10}, ok=False))
    out.append(pv("progress-unknown-status-shape-ok", "progress", "Unregistered but well-formed status passes the schema (fallback is semantic).",
                  ["§12.10"], {**prog, "status": "pondering"}))
    out.append(pv("progress-missing-session", "progress", "Session-scoped message without session.", ["§12.2"],
                  {k: v for k, v in prog.items() if k != "session"}, ok=False))

    # answer
    ans = session_msg("answer", "ans", sid, BPH, APH, NOW + 5, answered_by="user", media=AUDIO_SELECTION, transports=ONE_TRANSPORT)
    out.append(pv("answer-valid", "answer", "Answer with selection and exactly one transport.", ["§14.1", "§14.2"], ans))
    out.append(pv("answer-screening", "answer", "Screening answer with recvonly audio.", ["§14.4"],
                  {**ans, "answered_by": "screening",
                   "media": [{"type": "audio", "direction": "recvonly", "codecs": [{"id": "codec:audio/opus"}]}]}))
    out.append(pv("answer-missing-answered-by", "answer", "answered_by is required.", ["§14.3"],
                  {k: v for k, v in ans.items() if k != "answered_by"}, ok=False))
    out.append(pv("answer-two-transports", "answer", "An answer is a selection: exactly one transport.", ["§14.2"],
                  {**ans, "transports": ONE_TRANSPORT + [{"id": "transport:rtp-sdes"}]}, ok=False))
    out.append(pv("answer-update-reply", "answer", "Answer to an update via in_reply_to.", ["§12.8"], {**ans, "in_reply_to": uid("upd")}))
    out.append(pv("answer-unknown-answered-by-shape-ok", "answer", "Unregistered answered_by passes the schema (renders as service).",
                  ["§14.3"], {**ans, "answered_by": "butler"}))

    # reject / cancel / bye
    rej = session_msg("reject", "rej", sid, BPH, APH, NOW + 5, reason="user.declined")
    out.append(pv("reject-valid", "reject", "Reject with a registered reason.", ["§15.2"], rej))
    out.append(pv("reject-with-detail-retry", "reject", "Reject with detail and retry_after.", ["§15.2"],
                  {**rej, "reason": "endpoint.busy", "detail": "In another call", "retry_after": 120}))
    out.append(pv("reject-flat-token", "reject", "Legacy flat token lacks the category.condition shape.", ["§15.1"],
                  {**rej, "reason": "declined"}, ok=False))
    out.append(pv("reject-extension-namespace", "reject", "Extension-namespace token passes the shape rule.", ["§15.6"],
                  {**rej, "reason": "x-contactcenter.queue-full"}))
    out.append(pv("reject-missing-reason", "reject", "reason is required.", ["§15.2"],
                  {k: v for k, v in rej.items() if k != "reason"}, ok=False))
    can = session_msg("cancel", "can", sid, APH, F.BOB_WEB, NOW + 6, reason="user.cancelled")
    out.append(pv("cancel-valid", "cancel", "Cancel with user.cancelled.", ["§12.11"], can))
    out.append(pv("cancel-detail-too-long", "cancel", "detail above 1024 chars.", ["§15.2"], {**can, "detail": "x" * 1025}, ok=False))
    bye = session_msg("bye", "bye", sid, APH, BPH, NOW + 300, reason="user.hangup")
    out.append(pv("bye-valid", "bye", "Normal hangup.", ["§12.1"], bye))
    out.append(pv("bye-no-session", "bye", "bye without session.", ["§12.2"], {k: v for k, v in bye.items() if k != "session"}, ok=False))

    # update / info
    upd = session_msg("update", "upd", sid, BPH, APH, NOW + 60, answered_by="user",
                      media=[{"type": "video", "direction": "sendrecv", "codecs": [{"id": "codec:video/h264"}]}])
    out.append(pv("update-valid-escalation", "update", "Screening → user escalation update with video offer.", ["§12.8", "§14.4"], upd))
    out.append(pv("update-no-media", "update", "update MUST carry a media offer.", ["§12.8"],
                  {k: v for k, v in upd.items() if k != "media"}, ok=False))
    info = session_msg("info", "info", sid, BPH, APH, NOW + 6, about="transport:webrtc",
                       data={"candidates": [{"candidate": "candidate:1 1 udp 1 203.0.113.7 61481 typ srflx",
                                             "sdp_mid": "0", "sdp_m_line_index": 0}], "end_of_candidates": False})
    out.append(pv("info-valid-ice", "info", "info carrying trickle ICE candidates.", ["§12.12"], info))
    out.append(pv("info-missing-data", "info", "data is required.", ["§12.12"], {k: v for k, v in info.items() if k != "data"}, ok=False))
    out.append(pv("info-bad-about", "info", "about must be namespace:value.", ["§12.12"], {**info, "about": "webrtc"}, ok=False))

    # error
    err = {"dsip": F.VERSION_TRANSPORT, "type": "error", "id": uid("err"), "from": F.RELAY_WEB, "to": APH,
           "reason": "transport.rate-limited", "retry_after": 30, "in_reply_to": sid, "issued_at": NOW, "expires_at": NOW + 30}
    out.append(pv("error-transport-scoped", "error", "Transport-scoped error without session.", ["§15.4"], err))
    out.append(pv("error-session-scoped", "error", "Session-scoped error.", ["§12.4"],
                  {**err, "session": sid, "reason": "session.invalid-state", "from": BPH}))
    out.append(pv("error-missing-reason", "error", "reason is required.", ["§15.2"], {k: v for k, v in err.items() if k != "reason"}, ok=False))

    # hello
    hc = hello_client(on_behalf_of=F.BOB_WEB)
    out.append(pv("hello-client-valid", "hello", "Client hello with bindings and on_behalf_of.", ["§13.2"], hc))
    out.append(pv("hello-client-no-bindings", "hello", "Client form requires bindings.", ["§13.2"],
                  {k: v for k, v in hc.items() if k != "bindings"}, ok=False))
    out.append(pv("hello-with-session-field", "hello", "hello is session-scoped to nothing.", ["§13.2"], {**hc, "session": sid}, ok=False))
    hr = hello_relay(hc["id"])
    out.append(pv("hello-relay-valid", "hello", "Relay hello with in_reply_to and capabilities.", ["§13.2"], hr))
    out.append(pv("hello-relay-no-capabilities", "hello", "in_reply_to entails capabilities.", ["§13.2"],
                  {k: v for k, v in hr.items() if k != "capabilities"}, ok=False))
    out.append(pv("hello-relay-wrong-max-envelope", "hello", "max_envelope_bytes must equal the 65536 binding constant.", ["§13.2"],
                  {**hr, "capabilities": {**hr["capabilities"], "max_envelope_bytes": 32768}}, ok=False))
    out.append(pv("hello-relay-unknown-capability-ok", "hello", "Unknown capability fields MUST be ignored.", ["§13.2"],
                  {**hr, "capabilities": {**hr["capabilities"], "x_future": {"a": 1}}}))
    out.append(pv("hello-capabilities-without-in-reply-to", "hello", "capabilities entails in_reply_to.", ["§13.2"],
                  {k: v for k, v in hr.items() if k != "in_reply_to"}, ok=False))

    # introduction / grant
    intro = {"dsip": V, "type": "introduction", "id": uid("intro"), "from": F.did("carol-phone"), "to": F.BOB_WEB,
             "identity": {"display_name": "Carol Nguyen", "claims": []}, "purpose": "Following up from the meetup.",
             "issued_at": NOW, "expires_at": NOW + 604800}
    out.append(pv("introduction-valid", "introduction", "Valid introduction.", ["§19.4"], intro))
    out.append(pv("introduction-purpose-too-long", "introduction", "purpose over 280 characters.", ["§19.4"], {**intro, "purpose": "x" * 281}, ok=False))
    out.append(pv("introduction-with-media", "introduction", "An introduction cannot carry a media offer.", ["§19.4"],
                  {**intro, "media": MEDIA_OFFER}, ok=False))
    out.append(pv("introduction-contact-token", "introduction", "Introduction bearing an out-of-band contact token.", ["§19.4"],
                  {**intro, "contact_token": "tok_0123456789"}))
    grant = {"dsip": V, "type": "grant", "id": uid("grant"), "session": intro["id"], "from": F.BOB_WEB, "to": F.did("carol-phone"),
             "scope": ["dsip.invite"], "valid_until": NOW + 31536000, "issued_at": NOW + 600, "expires_at": NOW + 630}
    out.append(pv("grant-valid", "grant", "Grant referencing the introduction.", ["§19.4"], grant))
    out.append(pv("grant-scope-unprefixed", "grant", "Scope without the dsip. prefix.", ["§19.4"], {**grant, "scope": ["invite"]}, ok=False))
    out.append(pv("grant-empty-scope", "grant", "scope must be non-empty.", ["§19.4"], {**grant, "scope": []}, ok=False))

    # subscribe / notify / publish / unpublish
    sub = {"dsip": V, "type": "subscribe", "id": uid("sub"), "from": APH, "to": "did:web:example.com", "target": F.BOB_WEB,
           "events": ["presence"], "expires_in": 600, "issued_at": NOW, "expires_at": NOW + 30}
    out.append(pv("subscribe-valid", "subscribe", "Presence subscription.", ["§9.3"], sub))
    out.append(pv("subscribe-terminate", "subscribe", "expires_in 0 terminates.", ["§9.3"], {**sub, "expires_in": 0}))
    out.append(pv("subscribe-over-schema-ceiling", "subscribe", "expires_in above the 86,400 schema ceiling.", ["§9.3"],
                  {**sub, "expires_in": 100000}, ok=False))
    out.append(pv("subscribe-no-events", "subscribe", "events must be non-empty.", ["§9.3"], {**sub, "events": []}, ok=False))
    ntf = {"dsip": V, "type": "notify", "id": uid("ntf"), "from": "did:web:example.com", "to": APH, "subscription": sub["id"],
           "seq": 1, "state": "active", "body": {"type": "presence", "state": "available"}, "issued_at": NOW + 1, "expires_at": NOW + 31}
    out.append(pv("notify-initial", "notify", "First notify carrying current state.", ["§9.3"], ntf))
    out.append(pv("notify-terminated", "notify", "Terminal notify with reason.", ["§9.3"],
                  {**ntf, "seq": 9, "state": "terminated", "reason": "policy.terminated", "body": {}}))
    out.append(pv("notify-seq-zero", "notify", "seq starts at 1.", ["§9.3"], {**ntf, "seq": 0}, ok=False))
    out.append(pv("notify-bad-state", "notify", "state must be active|terminated.", ["§9.3"], {**ntf, "state": "paused"}, ok=False))
    pub = {"dsip": BCAST_V, "type": "publish", "id": uid("pub"), "from": "did:web:wxyz.com", "publisher": "did:web:wxyz.com",
           "stream_id": "did:web:wxyz.com:radio:main", "title": "WXYZ Live Radio", "state": "live",
           "variants": [{"id": "main-opus", "media": ["audio"], "codec": "codec:audio/opus", "transport": "transport:webrtc",
                         "uri": "wss://live.wxyz.com/dsip/webrtc/main"}],
           "policy": {"redistribution": "allowed-with-attribution"}, "issued_at": NOW, "expires_at": NOW + 300}
    out.append(pv("publish-valid", "publish", "Broadcast publication record.", ["§22.1"], pub))
    out.append(pv("publish-no-variants", "publish", "variants must be non-empty.", ["§22.1"], {**pub, "variants": []}, ok=False))
    out.append(pv("publish-bad-state", "publish", "Unknown publication state.", ["§22.1"], {**pub, "state": "paused"}, ok=False))
    unp = {"dsip": BCAST_V, "type": "unpublish", "id": uid("unpub"), "from": "did:web:wxyz.com", "publisher": "did:web:wxyz.com",
           "stream_id": "did:web:wxyz.com:radio:main", "publication": pub["id"], "issued_at": NOW + 600, "expires_at": NOW + 630}
    out.append(pv("unpublish-valid", "unpublish", "Withdraw a publication.", ["§22.1"], unp))
    out.append(pv("unpublish-missing-publication", "unpublish", "publication id is required.", ["§22.1"],
                  {k: v for k, v in unp.items() if k != "publication"}, ok=False))

    # envelope schema (shape only)
    from .common import signed
    env = signed(inv, "alice-phone")
    out.append(pv("envelope-shape-valid", "envelope", "Envelope object shape.", ["§10.2"], env))
    out.append(pv("envelope-shape-missing-signature", "envelope", "Envelope without signature.", ["§10.2"],
                  {k: v for k, v in env.items() if k != "signature"}, ok=False))
    return out
