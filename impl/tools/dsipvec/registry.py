"""DSIP Core v1.0 registries (spec §15.4, §14.3, §12.10, §9.3, §19.4).

Registries govern *membership*; schemas govern *shape*. Unknown-but-well-formed
values never fail here — they resolve to the category/receiver fallback.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

REASON_RE = re.compile(r"^[a-z][a-z0-9-]*\.[a-z][a-z0-9-]*$")

CATEGORIES = ("user", "endpoint", "identity", "session", "media", "policy", "transport", "gateway")

# token -> valid-on message types (spec §15.4 "Valid on" column)
REASONS: dict[str, tuple[str, ...]] = {
    "user.declined": ("reject", "bye"),
    "user.no-answer": ("reject",),
    "user.hangup": ("bye",),
    "user.cancelled": ("cancel",),
    "user.blocked": ("reject",),
    "endpoint.busy": ("reject",),
    "endpoint.unavailable": ("reject",),
    "endpoint.capability": ("reject",),
    "identity.not-in-service": ("reject", "error"),
    "identity.moved": ("reject",),
    "identity.suspended": ("reject",),
    "identity.unknown": ("reject", "error"),
    "session.expired": ("reject",),
    "session.timeout": ("cancel",),
    "session.glare": ("reject", "cancel"),
    "session.answered-elsewhere": ("cancel",),
    "session.already-answered": ("bye",),
    "session.cancelled": ("bye",),
    "session.invalid-state": ("error",),
    "session.unknown-session": ("error",),
    "session.update-pending": ("error",),
    "session.unsupported-core-version": ("reject", "error"),
    "session.unsupported-profile-version": ("reject", "error"),
    "session.unsupported-critical-extension": ("reject", "error"),
    "session.version-downgrade-detected": ("error",),
    "session.unsupported-wire-format": ("error",),
    "session.failed": ("reject", "bye", "error"),
    "media.unsupported": ("reject",),
    "media.offer-required": ("reject",),
    "media.encryption-required": ("reject",),
    "media.failed": ("bye",),
    "policy.trust-insufficient": ("reject",),
    "policy.first-contact-required": ("reject",),
    "policy.blocked": ("reject", "cancel"),
    "policy.terminated": ("bye",),
    "policy.rate-limited": ("reject", "error"),
    "transport.envelope-too-large": ("error",),
    "transport.hello-required": ("error",),
    "transport.hello-rejected": ("error",),
    "transport.routing-refused": ("error",),
    "transport.unknown-recipient": ("error",),
    "transport.rate-limited": ("error",),
    "gateway.unreachable": ("reject", "error"),
    "gateway.downgraded": ("error",),
    "gateway.mapped": ("reject", "bye", "error"),
}

# §15.4 also lists reasons valid on `notify` in prose (§9.3: session.expired,
# policy.terminated on terminated notifies). The registry column does not name
# notify; we accept tokens on notify without the valid-on warning.
REASON_BEARING_TYPES = ("reject", "cancel", "bye", "error")

ANSWERED_BY = ("user", "service", "screening", "gateway")
ANSWERED_BY_FALLBACK = "service"          # §14.3
PROGRESS_STATUS = ("trying", "ringing", "queued", "forwarded")
PROGRESS_STATUS_FALLBACK = "trying"      # §12.10
SUBSCRIPTION_EVENTS = {"presence": 3600, "publication": 86400}  # §9.3 hard caps
GRANT_SCOPES = ("dsip.invite", "dsip.subscribe")                # §19.4
MESSAGE_TYPES = (
    "invite", "progress", "answer", "reject", "cancel", "update", "info", "bye",
    "introduction", "grant", "publish", "subscribe", "notify", "unpublish", "error", "hello",
)
SESSION_SCOPED = ("progress", "answer", "reject", "cancel", "update", "info", "bye")


@dataclass(frozen=True)
class ReasonResolution:
    token: str
    effective: str
    fallback: str          # none | category | unknown-category
    valid_on_type: bool


def resolve_reason(token: str, msg_type: str) -> ReasonResolution:
    """§15.1 fallback rule. `msg_type` is the carrying message type."""
    category = token.split(".", 1)[0]
    if token in REASONS:
        valid = msg_type not in REASON_BEARING_TYPES or msg_type in REASONS[token]
        return ReasonResolution(token, token, "none", valid)
    if category in CATEGORIES:
        return ReasonResolution(token, token, "category", True)
    return ReasonResolution(token, "session.failed", "unknown-category", True)


def effective_answered_by(v: str) -> str:
    return v if v in ANSWERED_BY else ANSWERED_BY_FALLBACK


def effective_progress_status(v: str) -> str:
    return v if v in PROGRESS_STATUS else PROGRESS_STATUS_FALLBACK
