"""Adapter boundary.

An adapter is the only place a workforce agent touches a PurpleGuard
tool or engine. Each adapter is a real, read-only execution against the
authorized target and returns a normalized :class:`AdapterOutput`.

Two structured exceptions let an agent report *why* an execution could
not happen, instead of leaking an arbitrary exception across the
boundary or fabricating a result:

* :class:`InvalidTarget` - the task input is wrong (bad/absent target).
* :class:`EngineUnavailable` - the required engine primitive is
  missing for this target; the capability is honestly UNAVAILABLE.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AdapterOutput:
    findings: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    confidence: float = 0.0
    engine: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class AdapterError(Exception):
    """Base class for structured adapter failures."""


class InvalidTarget(AdapterError):
    """The supplied target cannot be used for this operation."""


class EngineUnavailable(AdapterError):
    """The engine primitive required for this capability is missing."""


class Adapter:
    """Base adapter. Subclasses implement :meth:`run`."""

    engine = ""

    def run(self, target: str | None, *, context: dict[str, Any] | None = None) -> AdapterOutput:
        raise NotImplementedError


__all__ = [
    "Adapter",
    "AdapterError",
    "AdapterOutput",
    "EngineUnavailable",
    "InvalidTarget",
]
