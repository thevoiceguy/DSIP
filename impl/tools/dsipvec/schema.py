"""JSON Schema validation against the canonical v0.6 schema set (spec §10.3).

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
SCHEMA_DIR = REPO_ROOT / "v0.6" / "dsip-schemas-v0.6-draft" / "dsip-schemas" / "schemas"


@lru_cache(maxsize=None)
def validator(name: str) -> Draft202012Validator:
    schema = json.loads((SCHEMA_DIR / f"{name}.schema.json").read_text())
    return Draft202012Validator(schema)


def schema_errors(name: str, payload) -> list[str]:
    v = local_validator(LOCAL_TYPES[name]) if name in LOCAL_TYPES else validator(name)
    return [e.message for e in v.iter_errors(payload)]


IMPL_SCHEMA_DIR = REPO_ROOT / "impl" / "schemas"
LOCAL_TYPES = {"reachability-hint": "reachability-hint", "broadcast.provenance": "broadcast-provenance"}


@lru_cache(maxsize=None)
def local_validator(name: str) -> Draft202012Validator:
    return Draft202012Validator(json.loads((IMPL_SCHEMA_DIR / f"{name}.schema.json").read_text()))


def dispatch_type(payload) -> str | None:
    """`message.schema.json` dispatch done natively: match on `type` (plus the implementation-local extension types)."""
    t = payload.get("type") if isinstance(payload, dict) else None
    if t in MESSAGE_TYPES or t in LOCAL_TYPES:
        return t
    return None
