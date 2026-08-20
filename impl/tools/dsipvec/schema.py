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
    return [e.message for e in validator(name).iter_errors(payload)]


def dispatch_type(payload) -> str | None:
    """`message.schema.json` dispatch done natively: match on `type`."""
    t = payload.get("type") if isinstance(payload, dict) else None
    return t if t in MESSAGE_TYPES else None
