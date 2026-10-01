"""Agent context / memory model.

Agents should not start from zero, and they should not receive unlimited context.
Context is scoped into five slices; the orchestrator hands an agent only what it
needs.

PurpleGuard remains the owner of authoritative security state; this module only
*reads* prior workforce results (and canonical findings) to assemble context.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .store import WorkforceStore


@dataclass(frozen=True)
class ContextBundle:
    global_context: dict[str, Any] = field(default_factory=dict)
    project_context: dict[str, Any] = field(default_factory=dict)
    task_context: dict[str, Any] = field(default_factory=dict)
    agent_context: dict[str, Any] = field(default_factory=dict)
    historical_context: dict[str, Any] = field(default_factory=dict)

    def keys(self) -> list[str]:
        return [
            name for name, value in (
                ("global", self.global_context),
                ("project", self.project_context),
                ("task", self.task_context),
                ("agent", self.agent_context),
                ("historical", self.historical_context),
            )
            if value
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "global": dict(self.global_context),
            "project": dict(self.project_context),
            "task": dict(self.task_context),
            "agent": dict(self.agent_context),
            "historical": dict(self.historical_context),
        }

    def for_agent(self, agent_id: str | None = None) -> dict[str, Any]:
        """A flattened view an agent may consume, bounded by history limit."""
        view: dict[str, Any] = {}
        view.update(self.global_context)
        view.update(self.project_context)
        view.update(self.task_context)
        if agent_id:
            view.update(self.agent_context.get(agent_id, {}))
        view.update(self.historical_context)
        return view


class ContextBuilder:
    def __init__(self, store: WorkforceStore | None = None, history_limit: int = 20) -> None:
        self._store = store or WorkforceStore()
        self._history_limit = history_limit

    def build(
        self,
        *,
        project_id: str,
        target: str | None,
        task: dict[str, Any] | None = None,
        policies: dict[str, Any] | None = None,
        agent_id: str | None = None,
        previous_results: list[dict[str, Any]] | None = None,
    ) -> ContextBundle:
        if previous_results is None:
            previous_results = [
                r for r in self._store.list_results() if r.get("metadata", {}).get("project_id", project_id) == project_id
            ]
        history = previous_results[-self._history_limit:]

        return ContextBundle(
            global_context={"policies": dict(policies or {}), "workforce": "purpleguard"},
            project_context={"project_id": project_id, "target": target},
            task_context=dict(task or {}),
            agent_context={agent_id: {"agent_id": agent_id}} if agent_id else {},
            historical_context={
                "previous_result_count": len(history),
                "previous_task_ids": [r.get("task_id") for r in history],
                "canonical_finding_count": len(self._store.list_canonical_findings()),
            },
        )


__all__ = ["ContextBundle", "ContextBuilder"]
