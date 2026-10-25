"""Presence vectors — the subscriber's combining rule (Presence Profile P§4, P§5; v0.17 draft, spec-gaps 135, 136) and
sealed records (P§12; spec-gaps 152–157)."""
from __future__ import annotations

from . import presence_sealed
from .presence_vectors import presence_vectors


def vectors() -> list[dict]:
    return presence_vectors() + presence_sealed.presence_vectors()
