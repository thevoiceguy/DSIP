"""JSON Schema validation against the canonical v0.7 schema set (spec §10.3).

Schemas are loaded from the spec folder — never copied — so this harness and
`dsip-schema` (which embeds the same files at build time) validate against one
source of truth.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from jsonschema import Draft202012Validator

from .registry import MESSAGE_TYPES

REPO_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_DIR = REPO_ROOT / "v0.7" / "dsip-schemas-v0.7-draft" / "dsip-schemas" / "schemas"

# `info.data` shapes by `about` (§12.12): validated for bindings this harness implements, ignored otherwise.
BINDING_DATA_SCHEMAS = {"transport:webrtc": "webrtc-info-data"}


@lru_cache(maxsize=None)
def validator(name: str) -> Draft202012Validator:
    schema = json.loads((SCHEMA_DIR / f"{name}.schema.json").read_text())
    return Draft202012Validator(schema)


def schema_errors(name: str, payload) -> list[str]:
    errs = [e.message for e in validator(name).iter_errors(payload)]
    if name == "info" and not errs and isinstance(payload, dict):
        binding = BINDING_DATA_SCHEMAS.get(payload.get("about"))
        if binding is not None:
            errs += [f"data: {e.message}" for e in validator(binding).iter_errors(payload.get("data"))]
    return errs


def dispatch_type(payload) -> str | None:
    """`message.schema.json` dispatch done natively: match on `type`."""
    t = payload.get("type") if isinstance(payload, dict) else None
    return t if t in MESSAGE_TYPES else None
