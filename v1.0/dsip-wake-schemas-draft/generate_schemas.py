#!/usr/bin/env python3
"""
DSIP Wake Profile (`wake/0.1`, draft) JSON Schema generator (draft 2020-12).

Profile schema set for `v1.0/dsip-wake-profile-v1.0-draft.md` (cited W§n): the four profile message payloads
(`wake-enrol`, `wake-accepted`, `wake-register`, `wake`; W§3–W§5), the `WakeRegistration` credential payload
(W§4.1) and the opened hint (W§6). Shared definitions are embedded into every file so each validates standalone.

Registry-governed values (provider, kind) are shape-validated with a token pattern; membership and fallback are
semantic checks, never schema enums.

Usage: python3 generate_schemas.py <output_dir>
"""
import copy
import json
import sys
from pathlib import Path

SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"
NS = "https://dsip.org/schema/wake/0.1/"  # placeholder; final $id base pends registry governance (core §24)

DEFS = {
    "ulid": {"type": "string", "pattern": "^[0-7][0-9A-HJKMNP-TV-Z]{25}$"},
    "did": {"type": "string", "pattern": "^did:[a-z0-9]+:[A-Za-z0-9.%_:-]+$"},
    "didKey": {"type": "string", "pattern": "^did:key:z[1-9A-HJ-NP-Za-km-z]+$",
               "description": "A did:key: the wake key (W§3). Its key type is checked when it is resolved (§7.2)."},
    "timestamp": {"type": "integer", "minimum": 0},
    "versionToken": {"type": "string", "pattern": "^\\d+\\.\\d+$"},
    "profileId": {"type": "string", "pattern": "^[a-z][a-z0-9-]*/\\d+\\.\\d+$"},
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
    "b64url": {"type": "string", "minLength": 1, "pattern": "^[A-Za-z0-9_-]+$", "description": "Unpadded base64url."},
    "token": {"type": "string", "pattern": "^[a-z][a-z0-9-]*$",
              "description": "Registry token; membership is a semantic check with a stated fallback."},
    "handle": {"type": "string", "minLength": 1, "maxLength": 512, "pattern": "^[A-Za-z0-9_-]+$",
               "description": "Opaque to everyone but the gateway that issued it (W§3)."},
    "envelope": {
        "type": "object",
        "properties": {"protected": {"$ref": "#/$defs/b64url"}, "payload": {"$ref": "#/$defs/b64url"},
                       "signature": {"$ref": "#/$defs/b64url"}},
        "required": ["protected", "payload", "signature"],
        "additionalProperties": False,
        "description": "A DSIP-JOSE envelope (§10.2): here the WakeRegistration credential (W§4.1).",
    },
    "sealed": {
        "type": "object",
        "properties": {"alg": {"type": "string", "minLength": 1}, "enc": {"$ref": "#/$defs/b64url"},
                       "ct": {"$ref": "#/$defs/b64url"}},
        "required": ["alg", "enc", "ct"],
        "additionalProperties": False,
        "description": "The sealed hint (W§6): HPKE to the registration's seal_key.",
    },
}


def envelope_payload(msg_type, props, required, description, extra=None):
    base_props = {
        "dsip": {"$ref": "#/$defs/versionBlock"},
        "type": {"const": msg_type},
        "id": {"$ref": "#/$defs/ulid"},
        "from": {"$ref": "#/$defs/did"},
        "to": {"$ref": "#/$defs/did"},
        "issued_at": {"$ref": "#/$defs/timestamp"},
        "expires_at": {"$ref": "#/$defs/timestamp"},
    }
    base_props.update(props)
    s = {
        "title": f"DSIP wake/0.1 {msg_type} payload",
        "description": description,
        "type": "object",
        "properties": base_props,
        "required": ["dsip", "type", "id", "from", "to", "issued_at", "expires_at"] + required,
        "additionalProperties": False,
    }
    s.update(extra or {})
    return s


SCHEMAS = {
    "wake-enrol": envelope_payload("wake-enrol", {
        "from": {"$ref": "#/$defs/didKey"},
        "provider": {"$ref": "#/$defs/token"},
        "app": {"type": "string", "minLength": 1, "maxLength": 256},
        "environment": {"enum": ["production", "sandbox"]},
        "token": {"type": "string", "minLength": 1, "maxLength": 4096},
    }, ["provider", "app", "token"], "A device enrols a platform push token with a push gateway, signed by its wake key (W§3)."),
    "wake-accepted": envelope_payload("wake-accepted", {
        "in_reply_to": {"$ref": "#/$defs/ulid"},
        "handle": {"$ref": "#/$defs/handle"},
    }, ["in_reply_to"], "A gateway's or waker's acceptance (W§3, W§4.2, W§5.3); `handle` only in answer to `wake-enrol`."),
    "wake-register": envelope_payload("wake-register", {
        "registration": {"$ref": "#/$defs/envelope"},
        "seal_key": {"type": "string", "pattern": "^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$",
                     "description": "An X25519 public key: the unpadded base64url of exactly 32 bytes."},
        "kinds": {"type": "array", "items": {"$ref": "#/$defs/token"}},
        "remove": {"const": True},
    }, [], "A device registers with, or removes itself from, a waker (W§4.2).", {
        "oneOf": [
            {"required": ["registration"], "not": {"required": ["remove"]}},
            {"required": ["remove"], "not": {"anyOf": [{"required": ["registration"]}, {"required": ["seal_key"]},
                                                       {"required": ["kinds"]}]}},
        ],
    }),
    "wake": envelope_payload("wake", {
        "registration": {"$ref": "#/$defs/envelope"},
        "kind": {"$ref": "#/$defs/token"},
        "session": {"$ref": "#/$defs/ulid"},
        "sealed": {"$ref": "#/$defs/sealed"},
        "deliver_by": {"$ref": "#/$defs/timestamp"},
    }, ["registration", "kind", "deliver_by"], "A waker asks a gateway to wake a device (W§5.2).", {
        "allOf": [{"if": {"properties": {"kind": {"enum": ["call", "call-ended"]}}, "required": ["kind"]},
                   "then": {"required": ["session"]}}],
    }),
    "wake-registration": {
        "title": "DSIP wake/0.1 WakeRegistration credential payload",
        "description": "A waker's permission to have a device woken through a gateway, signed by the wake key (W§4.1).",
        "type": "object",
        "properties": {
            "type": {"const": "WakeRegistration"},
            "key": {"$ref": "#/$defs/didKey"},
            "waker": {"$ref": "#/$defs/did"},
            "gateway": {"$ref": "#/$defs/did"},
            "handle": {"$ref": "#/$defs/handle"},
            "issued_at": {"$ref": "#/$defs/timestamp"},
            "expires_at": {"$ref": "#/$defs/timestamp"},
        },
        "required": ["type", "key", "waker", "gateway", "handle", "issued_at", "expires_at"],
        "additionalProperties": False,
    },
    "wake-hint": {
        "title": "DSIP wake/0.1 opened hint",
        "description": "The plaintext of a wake's `sealed` hint, trailing spaces removed (W§6).",
        "type": "object",
        "properties": {"from": {"$ref": "#/$defs/did"}, "on_behalf_of": {"$ref": "#/$defs/did"}},
        "required": ["from"],
        "additionalProperties": False,
    },
}


def finish(name, schema):
    s = {"$schema": SCHEMA_DIALECT, "$id": f"{NS}{name}.schema.json"}
    s.update(schema)
    s["$defs"] = copy.deepcopy(DEFS)
    return s


def main(outdir):
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    for name, schema in SCHEMAS.items():
        (out / f"{name}.schema.json").write_text(json.dumps(finish(name, schema), indent=2) + "\n")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "schemas")
