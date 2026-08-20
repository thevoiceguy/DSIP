#!/usr/bin/env python3
"""
DSIP JSON Schema generator.

Generates the DSIP Core v1.0 message schema set (draft 2020-12) from one
source of truth. Shared definitions are embedded into every schema file so
each file validates standalone in any conforming validator, with no $ref
resolution setup required.

Usage: python3 generate_schemas.py <output_dir>
"""
import json
import sys
import copy
from pathlib import Path

SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"
NS = "https://dsip.org/schema/1.0/"  # placeholder; final $id base pends registry governance (spec section 24)

# ---------------------------------------------------------------- shared defs

COMMON_DEFS = {
    "ulid": {
        "type": "string",
        "pattern": "^[0-7][0-9A-HJKMNP-TV-Z]{25}$",
        "description": "ULID (Crockford base32, 26 chars). Note: illustrative ids in spec prose (e.g. 01HZINVITEABC) are NOT valid ULIDs; conformant messages and test vectors use real ULIDs.",
    },
    "did": {
        "type": "string",
        "pattern": "^did:[a-z0-9]+:[A-Za-z0-9.%_:-]+$",
        "description": "Decentralized Identifier (DID Core syntax, method-specific validation out of scope here).",
    },
    "timestamp": {
        "type": "integer",
        "minimum": 0,
        "description": "Integer Unix timestamp, seconds (payload rules, spec 11.3: no floating point).",
    },
    "versionToken": {"type": "string", "pattern": "^\\d+\\.\\d+$"},
    "profileId": {
        "type": "string",
        "pattern": "^[a-z][a-z0-9-]*/\\d+\\.\\d+$",
        "description": "Registered profile or extension identifier with version, e.g. interactive-media/1.0",
    },
    "versionBlock": {
        "type": "object",
        "properties": {
            "core": {"$ref": "#/$defs/versionToken"},
            "min_core": {"$ref": "#/$defs/versionToken"},
            "profiles": {"type": "array", "items": {"$ref": "#/$defs/profileId"}},
            "extensions": {"type": "array", "items": {"$ref": "#/$defs/profileId"}},
            "critical": {"type": "array", "items": {"$ref": "#/$defs/profileId"}},
        },
        "required": ["core", "min_core", "profiles", "extensions", "critical"],
        "additionalProperties": False,
    },
    "reasonToken": {
        "type": "string",
        "pattern": "^[a-z][a-z0-9-]*\\.[a-z][a-z0-9-]*$",
        "description": "Namespaced reason token, category.condition (spec 13C). Registry membership is a semantic check, not a schema check; unknown conditions fall back per category.",
    },
    "codecId": {
        "type": "string",
        "pattern": "^codec:(audio|video|text|application)/[a-z0-9.+-]+$",
    },
    "codec": {
        "type": "object",
        "properties": {"id": {"$ref": "#/$defs/codecId"}},
        "required": ["id"],
        "additionalProperties": True,
        "description": "Codec descriptor. Normative form is an object with registered id plus codec-specific parameters (resolves the 14.2/15.3 draft inconsistency in favor of 14.2 objects).",
    },
    "transportId": {"type": "string", "pattern": "^transport:[a-z0-9-]+$"},
    "transportDescriptor": {
        "type": "object",
        "properties": {"id": {"$ref": "#/$defs/transportId"}},
        "required": ["id"],
        "additionalProperties": True,
    },
    "mediaDescriptor": {
        "type": "object",
        "properties": {
            "type": {"enum": ["audio", "video", "text", "application"]},
            "purpose": {
                "type": "string",
                "pattern": "^[a-z][a-z0-9-]*$",
                "description": "Registered media purpose, e.g. sign-language, caption (spec 20).",
            },
            "direction": {"enum": ["sendrecv", "sendonly", "recvonly", "inactive"]},
            "codecs": {"type": "array", "minItems": 1, "items": {"$ref": "#/$defs/codec"}},
        },
        "required": ["type", "direction", "codecs"],
        "additionalProperties": True,
    },
    "policy": {
        "type": "object",
        "propertyNames": {"pattern": "^[a-z][a-z0-9_]*$"},
        "additionalProperties": {"type": "string", "pattern": "^[a-z][a-z0-9-]*$"},
        "description": "Registered policy keys to registered policy values (spec 14.4). Registry membership is a semantic check.",
    },
    "identityInfo": {
        "type": "object",
        "properties": {
            "display_name": {"type": "string", "maxLength": 256},
            "claims": {"type": "array", "items": {"type": "object"}},
        },
        "additionalProperties": False,
        "description": "Unverified-by-default identity presentation; claims carry VC presentations (spec 17). Display fields are claims, not truth.",
    },
}

def base(msg_type, *, session_scoped, has_to=True, extra_props=None,
         extra_required=None, description="", no_additional=True):
    props = {
        "dsip": {"$ref": "#/$defs/versionBlock"},
        "type": {"const": msg_type},
        "id": {"$ref": "#/$defs/ulid"},
        "from": {"$ref": "#/$defs/did"},
        "issued_at": {"$ref": "#/$defs/timestamp"},
        "expires_at": {"$ref": "#/$defs/timestamp"},
    }
    required = ["dsip", "type", "id", "from", "issued_at", "expires_at"]
    if has_to:
        props["to"] = {"$ref": "#/$defs/did"}
        required.append("to")
    if session_scoped:
        props["session"] = {"$ref": "#/$defs/ulid"}
        required.append("session")
    if extra_props:
        props.update(extra_props)
    if extra_required:
        required.extend(extra_required)
    schema = {
        "$schema": SCHEMA_DIALECT,
        "$id": f"{NS}{msg_type}.schema.json",
        "title": f"DSIP {msg_type} payload",
        "description": description,
        "type": "object",
        "properties": props,
        "required": required,
        "additionalProperties": not no_additional,
        "$defs": copy.deepcopy(COMMON_DEFS),
    }
    return schema

REASON_FIELDS = {
    "reason": {"$ref": "#/$defs/reasonToken"},
    "detail": {
        "type": "string",
        "maxLength": 1024,
        "description": "Free-text elaboration. A claim by the signer; clients must not render as independently verified (spec 13C.3.2).",
    },
    "retry_after": {"type": "integer", "minimum": 0},
}

# ---------------------------------------------------------------- messages

schemas = {}

schemas["invite"] = base(
    "invite", session_scoped=False,
    description="Start an interactive session. MUST carry a media offer and at least one transport; offerless invites are rejected with media.offer-required (spec 13C.2.2).",
    extra_props={
        "intent": {"type": "string", "pattern": "^[a-z][a-z0-9-]*$"},
        "grant": {"$ref": "#/$defs/ulid",
                  "description": "Optional id of a contact grant (spec 19.4) authorizing this invite, to aid stateless relays."},
        "identity": {"$ref": "#/$defs/identityInfo"},
        "media": {"type": "array", "minItems": 1, "items": {"$ref": "#/$defs/mediaDescriptor"}},
        "transports": {"type": "array", "minItems": 1, "items": {"$ref": "#/$defs/transportDescriptor"}},
        "policy": {"$ref": "#/$defs/policy"},
    },
    extra_required=["media", "transports"],
)

schemas["progress"] = base(
    "progress", session_scoped=True,
    description="Pre-answer handling status. queued REQUIRES queue_timeout (spec 13A.6.1). Commits no media.",
    extra_props={
        "status": {
            "type": "string",
            "pattern": "^[a-z][a-z0-9-]*$",
            "description": "Registered: trying, ringing, queued, forwarded. Unknown values are treated as trying by receivers.",
        },
        "ring_timeout": {"type": "integer", "minimum": 30, "maximum": 300},
        "queue_timeout": {"type": "integer", "minimum": 1, "maximum": 1800},
    },
    extra_required=["status"],
)
schemas["progress"]["if"] = {"properties": {"status": {"const": "queued"}}}
schemas["progress"]["then"] = {"required": ["queue_timeout"]}

schemas["answer"] = base(
    "answer", session_scoped=True,
    description="Commit to the negotiated session. Means a verified delegated endpoint commits to media, NOT that a human accepted; answered_by distinguishes (spec 13C.2). Valid for initial establishment and for update renegotiation responses.",
    extra_props={
        "answered_by": {
            "type": "string",
            "pattern": "^[a-z][a-z0-9-]*$",
            "description": "Registered: user, service, screening, gateway. Unknown values render as service.",
        },
        "media": {"type": "array", "minItems": 1, "items": {"$ref": "#/$defs/mediaDescriptor"}},
        "transports": {"type": "array", "minItems": 1, "maxItems": 1, "items": {"$ref": "#/$defs/transportDescriptor"}},
        "policy": {"$ref": "#/$defs/policy"},
        "in_reply_to": {"$ref": "#/$defs/ulid", "description": "id of the update being answered, when responding to renegotiation (spec 13A.4.8). Absent on initial answer."},
    },
    extra_required=["answered_by", "media", "transports"],
)

schemas["reject"] = base(
    "reject", session_scoped=True,
    description="Decline a session or an update. reason is a namespaced token from the unified registry (spec 13C).",
    extra_props={**copy.deepcopy(REASON_FIELDS),
                 "in_reply_to": {"$ref": "#/$defs/ulid", "description": "id of the update being rejected, when rejecting renegotiation. Absent when rejecting the invite itself."}},
    extra_required=["reason"],
)

schemas["cancel"] = base(
    "cancel", session_scoped=True,
    description="Withdraw an invite before answer. Only valid pre-ACTIVE; must be signed by the inviting identity or its delegate (spec 13A.6.2).",
    extra_props=copy.deepcopy(REASON_FIELDS),
    extra_required=["reason"],
)

schemas["update"] = base(
    "update", session_scoped=True,
    description="Renegotiate an established session. Always carries a media offer from its sender; one outstanding per session across both directions (spec 13A.4.8).",
    extra_props={
        "media": {"type": "array", "minItems": 1, "items": {"$ref": "#/$defs/mediaDescriptor"}},
        "transports": {"type": "array", "minItems": 1, "items": {"$ref": "#/$defs/transportDescriptor"}},
        "answered_by": {"type": "string", "pattern": "^[a-z][a-z0-9-]*$",
                        "description": "Optional on update: signals role transition, e.g. screening -> user escalation (spec 13C.2.4)."},
        "policy": {"$ref": "#/$defs/policy"},
    },
    extra_required=["media"],
)

schemas["bye"] = base(
    "bye", session_scoped=True,
    description="End an established session. reason from the unified registry; normal hangup is user.hangup.",
    extra_props=copy.deepcopy(REASON_FIELDS),
    extra_required=["reason"],
)

schemas["error"] = base(
    "error", session_scoped=False,
    description="Protocol/policy failure report. session present only when the error is session-scoped; transport-scoped errors (transport.*) omit it.",
    extra_props={
        **copy.deepcopy(REASON_FIELDS),
        "session": {"$ref": "#/$defs/ulid"},
        "in_reply_to": {"$ref": "#/$defs/ulid", "description": "id of the envelope that provoked the error, when known."},
    },
    extra_required=["reason"],
)

schemas["hello"] = base(
    "hello", session_scoped=False, has_to=False,
    description="Transport connection binding (spec 13B.2.4). Client form: bindings required. Relay form: in_reply_to + capabilities required (mutually entailed).",
    extra_props={
        "on_behalf_of": {"$ref": "#/$defs/did"},
        "bindings": {"type": "array", "minItems": 1,
                     "items": {"type": "string", "pattern": "^[a-z0-9]+/\\d+\\.\\d+$"}},
        "in_reply_to": {"$ref": "#/$defs/ulid"},
        "capabilities": {
            "type": "object",
            "properties": {
                "max_envelope_bytes": {"const": 65536,
                                       "description": "Fixed binding constant of ws/1.0."},
                "store_and_forward": {"type": "boolean"},
                "offline_retention_s": {"type": "integer", "minimum": 0},
                "rate_limit": {
                    "type": "object",
                    "properties": {
                        "envelopes_per_minute": {"type": "integer", "minimum": 1},
                        "invites_per_minute": {"type": "integer", "minimum": 1},
                    },
                    "additionalProperties": True,
                },
                "push_wake": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["max_envelope_bytes"],
            "additionalProperties": True,
        },
    },
)
schemas["hello"]["allOf"] = [
    {"if": {"required": ["in_reply_to"]}, "then": {"required": ["capabilities"]}},
    {"if": {"required": ["capabilities"]}, "then": {"required": ["in_reply_to"]}},
    {"if": {"not": {"required": ["in_reply_to"]}}, "then": {"required": ["bindings"]}},
]

# Broadcast profile. publish follows spec 16.1; subscribe/notify/unpublish are
# PROVISIONAL pending the broadcast profile's own subscription protocol section.
schemas["publish"] = base(
    "publish", session_scoped=False, has_to=False,
    description="Signed broadcast publication record (spec 16.1).",
    extra_props={
        "publisher": {"$ref": "#/$defs/did"},
        "stream_id": {"type": "string", "minLength": 1},
        "title": {"type": "string", "maxLength": 512},
        "state": {"enum": ["live", "scheduled", "ended"]},
        "variants": {
            "type": "array", "minItems": 1,
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string", "minLength": 1},
                    "media": {"type": "array", "minItems": 1,
                              "items": {"enum": ["audio", "video", "text"]}},
                    "codec": {"$ref": "#/$defs/codecId"},
                    "transport": {"$ref": "#/$defs/transportId"},
                    "uri": {"type": "string", "format": "uri"},
                },
                "required": ["id", "media", "codec", "transport", "uri"],
                "additionalProperties": True,
            },
        },
        "policy": {"$ref": "#/$defs/policy"},
    },
    extra_required=["publisher", "stream_id", "state", "variants"],
)

schemas["subscribe"] = base(
    "subscribe", session_scoped=False,
    description="Soft-state subscription to presence or publication events (spec 9.3). expires_in 0 terminates; renewal is a fresh subscribe. Per-event lifetime caps (presence 3600, publication 86400) are semantic checks.",
    extra_props={
        "target": {"type": "string", "minLength": 1,
                   "description": "Subject DID or stream_id being subscribed to. to= the authority answering for it."},
        "events": {"type": "array", "minItems": 1,
                   "items": {"type": "string", "pattern": "^[a-z][a-z0-9-]*$"},
                   "description": "Registered event classes (dsip-subscription-event): presence, publication."},
        "expires_in": {"type": "integer", "minimum": 0, "maximum": 86400},
        "claims": {"type": "array", "items": {"type": "object"},
                   "description": "Optional VC presentations as authorization evidence."},
        "capability": {"type": "string", "maxLength": 2048,
                       "description": "Optional opaque authorization token previously issued by the target authority."},
    },
    extra_required=["target", "events", "expires_in"],
)

schemas["notify"] = base(
    "notify", session_scoped=False,
    description="Subscription update (spec 9.3). First notify carries current state; state=terminated is final and SHOULD carry reason. seq orders notifies within a subscription.",
    extra_props={
        "subscription": {"$ref": "#/$defs/ulid",
                         "description": "id of the subscribe this notify serves."},
        "seq": {"type": "integer", "minimum": 1},
        "state": {"enum": ["active", "terminated"]},
        "reason": {"$ref": "#/$defs/reasonToken"},
        "body": {"type": "object",
                 "description": "Event record; MAY be a full signed envelope for third-party verifiability (RECOMMENDED when notifier is not the subject)."},
    },
    extra_required=["subscription", "seq", "state", "body"],
)

schemas["unpublish"] = base(
    "unpublish", session_scoped=False, has_to=False,
    description="Withdraw a publication.",
    extra_props={
        "publisher": {"$ref": "#/$defs/did"},
        "stream_id": {"type": "string", "minLength": 1},
        "publication": {"$ref": "#/$defs/ulid",
                        "description": "id of the publish being withdrawn."},
    },
    extra_required=["publisher", "stream_id", "publication"],
)


schemas["info"] = base(
    "info", session_scoped=True,
    description="Transport-binding data within an established session, e.g. trickle ICE candidates (spec 12.12). ACTIVE-only, never critical, no reply, must not alter negotiated parameters. Unknown about values are ignored silently.",
    extra_props={
        "about": {"type": "string", "pattern": "^[a-z][a-z0-9-]*:[a-z0-9.-]+$",
                  "description": "Registered namespace the data belongs to (dsip-info-about), e.g. transport:webrtc."},
        "data": {"type": "object",
                 "description": "Structure defined by the binding named in about."},
    },
    extra_required=["about", "data"],
)

schemas["introduction"] = base(
    "introduction", session_scoped=False,
    description="First-contact request (spec 19.4): media-less, session-less, encoded envelope capped at 4096 bytes (semantic check), validity up to 7 days. purpose and identity fields are claims. Never rendered as a call.",
    extra_props={
        "identity": {"$ref": "#/$defs/identityInfo"},
        "purpose": {"type": "string", "maxLength": 280,
                    "description": "Short stated purpose; a claim, rendered attributed and unverified."},
        "contact_token": {"type": "string", "maxLength": 2048,
                          "description": "Optional out-of-band token from the recipient authority; valid tokens SHOULD bypass rate limits."},
    },
    extra_required=["identity"],
)

schemas["grant"] = base(
    "grant", session_scoped=True,
    description="Signed contact grant answering an introduction (spec 19.4); session references the introduction id. The consent receipt in message form: scoped, time-bounded via valid_until, revocable at the granting side.",
    extra_props={
        "scope": {"type": "array", "minItems": 1,
                  "items": {"type": "string", "pattern": "^dsip\\.[a-z][a-z0-9.-]*$"},
                  "description": "Registered grant scopes (dsip-grant-scope): dsip.invite, dsip.subscribe."},
        "valid_until": {"$ref": "#/$defs/timestamp",
                        "description": "Grant lifetime, independent of the envelope delivery expiry."},
    },
    extra_required=["scope", "valid_until"],
)

# ---------------------------------------------------------------- envelope & dispatcher

envelope = {
    "$schema": SCHEMA_DIALECT,
    "$id": f"{NS}envelope.schema.json",
    "title": "DSIP-JOSE signed envelope",
    "description": "JWS envelope (spec 11.2). The payload member is the base64url-encoded DSIP JSON payload validated by the per-message schemas.",
    "type": "object",
    "properties": {
        "protected": {"type": "string", "pattern": "^[A-Za-z0-9_-]+$"},
        "payload": {"type": "string", "pattern": "^[A-Za-z0-9_-]+$"},
        "signature": {"type": "string", "pattern": "^[A-Za-z0-9_-]+$"},
    },
    "required": ["protected", "payload", "signature"],
    "additionalProperties": False,
}

dispatcher = {
    "$schema": SCHEMA_DIALECT,
    "$id": f"{NS}message.schema.json",
    "title": "DSIP payload dispatcher",
    "description": "Validates any DSIP payload by dispatching on type. Relative $refs require a resolver configured with this directory as base; individual schemas are standalone.",
    "oneOf": [
        {"allOf": [
            {"properties": {"type": {"const": t}}, "required": ["type"]},
            {"$ref": f"{t}.schema.json"},
        ]}
        for t in sorted(schemas)
    ],
}

# ---------------------------------------------------------------- write

def main(outdir):
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    for name, schema in schemas.items():
        (out / f"{name}.schema.json").write_text(json.dumps(schema, indent=2) + "\n")
    (out / "envelope.schema.json").write_text(json.dumps(envelope, indent=2) + "\n")
    (out / "message.schema.json").write_text(json.dumps(dispatcher, indent=2) + "\n")
    print(f"wrote {len(schemas) + 2} schemas to {out}")

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "schemas")
