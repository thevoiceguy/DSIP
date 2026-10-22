"""Presence Profile (`presence/0.1`, v0.17 draft) — the subscriber's combining rule and the profile's timers.

Spec: P§4 (several devices' records combined into one identity's presence), P§5 (the open state registry and its
fallback), P§8 (timers). The authority's side of P§3 is `broadcast.Authority`.
"""
from __future__ import annotations

from .registry import PRESENCE_STATES, PRESENCE_STATE_FALLBACK

RECORD_MIN_LIFETIME_S = 60      # P§8
RECORD_MAX_LIFETIME_S = 3600    # P§8, §12.9
PRESENCE_GRACE_S = 60           # P§8 T-Presence-Grace default (bounds 0–300)
PUBLISH_INTERVAL_S = 5          # P§8: between two accepted records of one device

# P§4 starting order, highest first
RANK = {"dnd": 4, "busy": 3, "available": 2, "away": 1, "offline": 0}


def effective_state(token: str) -> str:
    """P§5: a registered state stands; an unknown one is shown as available."""
    return token if token in PRESENCE_STATES else PRESENCE_STATE_FALLBACK


def aggregate(records: list[dict], asserted: str | None, now: int) -> dict:
    """P§4: the identity's presence from the records a subscriber holds (each `{state, expires_at, device?}`) and the
    body's assertion. Returns `{state, token, source}`: the effective state, the token that won, and `record`,
    `assertion` or `none`."""
    # (rank, record before assertion, registered first, token in code-point order)
    candidates = [(r["state"], "record") for r in records if r["expires_at"] > now]
    if asserted == "available":
        candidates.append(("available", "assertion"))
    if not candidates:
        return {"state": "offline", "token": "offline", "source": "none"}

    def key(c):
        token, source = c
        return (-RANK[effective_state(token)], source != "record", token not in PRESENCE_STATES, token)

    token, source = min(candidates, key=key)
    return {"state": effective_state(token), "token": token, "source": source}


def run(v: dict) -> dict:
    """The `presence` vector kind: `input.check` `aggregate` (P§4)."""
    i = v["input"]
    if i["check"] == "aggregate":
        return aggregate(i["records"], i.get("asserted"), v["context"]["now"])
    raise ValueError(f"unknown presence check {i['check']}")
