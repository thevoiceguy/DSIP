"""Presence vectors — the subscriber's combining rule (Presence Profile P§4, P§5; v0.17 draft, spec-gaps 135, 136)."""
from __future__ import annotations

from .presence_vectors import presence_vectors


def vectors() -> list[dict]:
    return presence_vectors()
