"""Generic engine-backed agent.

One class drives every capability that is backed by a real adapter.
It validates nothing itself beyond the adapter contract: it runs the
adapter and normalizes the outcome into an :class:`AgentResult`.

Execution state is always truthful:

* adapter returns             -> ``completed`` (or the adapter's own result)
* wrong/absent target         -> ``rejected``  (INVALID_TASK)
* engine primitive missing    -> ``unavailable`` (ENGINE_UNAVAILABLE)
* any other exception         -> ``failed``    (EXECUTION_ERROR)

No path ever fabricates a successful finding.
"""

from __future__ import annotations

from typing import Any

from ..adapters.base import Adapter, EngineUnavailable, InvalidTarget
from ..contracts import (
    AgentResult,
    AgentStatus,
    AgentStatusReason,
    StructuredError,
    Task,
)


class EngineAgent:
    def __init__(
        self,
        agent_id: str,
        role: str,
        permissions: frozenset[str],
        adapter: Adapter,
        *,
        engine: str = "",
    ) -> None:
        self.agent_id = agent_id
        self.role = role
        self.permissions = frozenset(permissions)
        self.adapter = adapter
        self.engine = engine or getattr(adapter, "engine", "")

    def execute(
        self,
        task: Task,
        *,
        target: str | None,
        context: dict[str, Any] | None = None,
    ) -> AgentResult:
        base = {
            "agent_id": self.agent_id,
            "task_id": task.task_id,
            "correlation_id": task.correlation_id,
            "role": self.role,
        }

        try:
            output = self.adapter.run(target, context=context)
        except InvalidTarget as exc:
            return self._fail(base, AgentStatusReason.INVALID_TASK, str(exc), AgentStatus.REJECTED)
        except EngineUnavailable as exc:
            return self._fail(base, AgentStatusReason.ENGINE_UNAVAILABLE, str(exc), AgentStatus.UNAVAILABLE)
        except Exception as exc:  # normalized; never leaked across the boundary
            return self._fail(
                base,
                AgentStatusReason.EXECUTION_ERROR,
                f"{self.agent_id} adapter raised",
                AgentStatus.FAILED,
                detail={"exception": type(exc).__name__},
            )

        return AgentResult(
            **base,
            status=AgentStatus.COMPLETED.value,
            findings=tuple(output.findings),
            evidence=tuple(output.evidence),
            recommendations=tuple(output.recommendations),
            confidence=output.confidence,
            metadata={
                **dict(output.metadata),
                "engine": self.engine,
                "permissions_used": sorted(self.permissions),
                "playbook": task.playbook,
                "finding_count": len(output.findings),
            },
        )

    @staticmethod
    def _fail(
        base: dict[str, Any],
        reason: AgentStatusReason,
        message: str,
        status: AgentStatus,
        detail: dict[str, Any] | None = None,
    ) -> AgentResult:
        return AgentResult(
            **base,
            status=status.value,
            confidence=0.0,
            errors=(StructuredError(code=reason.value, message=message, detail=dict(detail or {})),),
        )


__all__ = ["EngineAgent"]
