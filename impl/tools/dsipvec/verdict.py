"""Verdict type shared by every pipeline stage."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Verdict:
    verdict: str                       # accept | reject
    code: str | None = None
    reason: str | None = None
    detail: str | None = None          # free text for humans; never compared
    extra: dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def accept(**extra) -> "Verdict":
        return Verdict("accept", extra=extra)

    @staticmethod
    def reject(code: str, reason: str | None = None, detail: str | None = None) -> "Verdict":
        return Verdict("reject", code=code, reason=reason, detail=detail)

    @property
    def ok(self) -> bool:
        return self.verdict == "accept"

    def to_expect(self) -> dict:
        """The comparable projection (what a vector's `expect` holds)."""
        if self.ok:
            out = {"verdict": "accept"}
            out.update(self.extra)
            return out
        out = {"verdict": "reject", "code": self.code}
        if self.reason:
            out["reason"] = self.reason
        return out
