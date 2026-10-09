"""JSON Schema validation against the canonical v0.8 schema set (spec §10.3).

Schemas are loaded from the spec folder — never copied — so this harness and
`dsip-schema` (which embeds the same files at build time) validate against one
source of truth.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

from jsonschema import Draft202012Validator, validators
from jsonschema.exceptions import ValidationError

from .registry import MESSAGE_TYPES

REPO_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_DIR = REPO_ROOT / "v0.12" / "dsip-schemas-v0.12-draft" / "dsip-schemas" / "schemas"

# `info.data` shapes by `about` (§12.12): validated for bindings this harness implements, ignored otherwise.
BINDING_DATA_SCHEMAS = {"transport:webrtc": "webrtc-info-data", "media:dtmf": "dtmf-info-data"}


@lru_cache(maxsize=None)
def ecma_regex(pattern: str) -> re.Pattern:
    """JSON Schema patterns are ECMA-262 regexes (draft 2020-12 §6.4). Python's differ in two ways that matter here:
    `$` also matches before a final newline, and `\\d` matches non-ASCII digits. An unescaped `$` outside a class
    becomes `\\Z`, and the pattern is ASCII. The other runners (Rust `regex`, JavaScript) need no translation."""
    out, i, in_class = [], 0, False
    while i < len(pattern):
        c = pattern[i]
        if c == "\\":
            out.append(pattern[i:i + 2])
            i += 2
            continue
        if c == "[":
            in_class = True
        elif c == "]":
            in_class = False
        out.append("\\Z" if c == "$" and not in_class else c)
        i += 1
    return re.compile("".join(out), re.ASCII)


def _ecma_pattern(v, pattern, instance, schema):
    if v.is_type(instance, "string") and not ecma_regex(pattern).search(instance):
        yield ValidationError(f"{instance!r} does not match {pattern!r}")


# The validator every schema check in this harness uses: draft 2020-12 with ECMA-262 `pattern` semantics.
Validator = validators.extend(Draft202012Validator, {"pattern": _ecma_pattern})


@lru_cache(maxsize=None)
def validator(name: str) -> Draft202012Validator:
    schema = json.loads((SCHEMA_DIR / f"{name}.schema.json").read_text())
    return Validator(schema)


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
