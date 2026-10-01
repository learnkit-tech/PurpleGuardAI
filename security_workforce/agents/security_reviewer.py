"""security-reviewer agent — the first real workforce vertical slice.

Registry entry: ``security_workforce/registry/agents.json``.
Role source: ``ecc/agents/security-reviewer.md`` (adapted).
Permissions: OBSERVE + ANALYZE only. Read-only; never modifies source.
"""

from __future__ import annotations

import os
from typing import Any

from ..adapters.scanner import ScannerAdapter
from ..contracts import (
    AgentResult,
    AgentStatus,
    AgentStatusReason,
    StructuredError,
    Task,
)

AGENT_ID = "security-reviewer"
ROLE = "vulnerability_analysis"
PERMISSIONS = frozenset({"observe", "analyze"})


class SecurityReviewerAgent:
    def __init__(self, adapter: ScannerAdapter | None = None) -> None:
        self._adapter = adapter or ScannerAdapter()

    def execute(self, task: Task, *, target: str | None, context: dict[str, Any] | None = None) -> AgentResult:
        base = {
            "agent_id": AGENT_ID,
            "task_id": task.task_id,
            "correlation_id": task.correlation_id,
            "role": ROLE,
        }

        if not isinstance(target, str) or not target.strip():
            return self._fail(base, AgentStatusReason.INVALID_TASK, "security.review requires a target path", AgentStatus.REJECTED)
        if not os.path.isdir(target):
            return self._fail(base, AgentStatusReason.INVALID_TASK, f"target is not a directory: {target!r}", AgentStatus.REJECTED)

        try:
            findings, evidence, recommendations = self._adapter.review(target)
        except Exception as exc:  # normalized; never leaked across the boundary
            return self._fail(
                base,
                AgentStatusReason.EXECUTION_ERROR,
                "static scan failed",
                AgentStatus.FAILED,
                detail={"exception": type(exc).__name__},
            )

        return AgentResult(
            **base,
            status=AgentStatus.COMPLETED.value,
            findings=tuple(findings),
            evidence=tuple(evidence),
            recommendations=tuple(recommendations) or ("No static findings; no remediation proposed.",),
            confidence=1.0,  # deterministic static analysis over a real target
            metadata={
                "target": os.path.abspath(target),
                "finding_count": len(findings),
                "deterministic": True,
                "scanner": "scanner.engine.SecurityScanner",
                "context_keys": sorted(context) if context else [],
                "permissions_used": sorted(PERMISSIONS),
                "playbook": task.playbook,
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
            metadata={"permissions_used": sorted(PERMISSIONS)},
        )
