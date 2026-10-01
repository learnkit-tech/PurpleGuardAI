"""Orchestration adapters (real execution over workforce state).

These two agents do not touch a code-scanning engine; they operate on
real workforce state - the agent registry, the playbook registry, and
persisted results - to produce a task plan and coordination decisions.
Their output is real (derived from real registry/store data), never
invented.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ..contracts import Evidence, ValidationState
from ..playbooks import load_playbooks
from .base import Adapter, AdapterOutput, InvalidTarget


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class PlanningAdapter(Adapter):
    engine = "security_workforce.orchestrator.WorkforceOrchestrator"

    def __init__(self, registry: dict[str, Any] | None = None) -> None:
        self._registry = registry or {}

    def run(self, target: str | None, *, context: dict[str, Any] | None = None) -> AdapterOutput:
        playbooks = load_playbooks()
        executable = sorted(
            agent_id for agent_id, spec in self._registry.items()
            if getattr(spec, "implementation", "") == "available"
        )

        plan = []
        for playbook_id, playbook in playbooks.items():
            participants = [
                agent for agent in playbook.get("participating_agents", [])
                if agent in executable
            ]
            if not participants and playbook.get("participating_agents"):
                continue
            plan.append({
                "playbook": playbook_id,
                "steps": playbook.get("steps", []),
                "executable_agents": participants,
            })

        if not plan:
            raise InvalidTarget("no playbook can be scheduled with the executable agents")

        evidence = [
            Evidence(
                what_tested="assessment planning",
                where_tested="<workforce-registry>",
                what_happened=f"{len(plan)} playbook(s) schedulable with executable agents",
                why_it_matters="A plan only schedules capabilities that genuinely execute.",
                reproduction="security_workforce planning",
                validation_state=ValidationState.UNVALIDATED.value,
                timestamp=_now(),
            ).to_dict()
        ]

        return AdapterOutput(
            findings=[],
            evidence=evidence,
            recommendations=[f"Run playbook {item['playbook']}." for item in plan],
            confidence=1.0,
            engine=self.engine,
            metadata={"plan": plan, "executable_agents": executable},
        )


class CoordinationAdapter(Adapter):
    engine = "security_workforce.orchestrator.WorkforceOrchestrator"

    def __init__(self, store) -> None:
        self._store = store

    def run(self, target: str | None, *, context: dict[str, Any] | None = None) -> AdapterOutput:
        canonical = self._store.list_canonical_findings()

        escalations = []
        for finding in canonical:
            state = finding.get("validation_state")
            severity = str(finding.get("severity", "")).upper()
            if severity in {"HIGH", "CRITICAL"} and state != "corroborated":
                escalations.append({
                    "fingerprint": finding.get("fingerprint"),
                    "rule_id": finding.get("rule_id"),
                    "severity": severity,
                    "validation_state": state,
                    "reason": "high-risk finding lacks independent corroboration",
                })

        evidence = [
            Evidence(
                what_tested="workforce coordination state",
                where_tested="<workforce-store>",
                what_happened=f"{len(canonical)} canonical finding(s), {len(escalations)} escalation(s)",
                why_it_matters="Uncorroborated high-risk findings must reach a human.",
                reproduction="security_workforce coordination",
                validation_state=ValidationState.UNVALIDATED.value,
                timestamp=_now(),
            ).to_dict()
        ]

        return AdapterOutput(
            findings=[],
            evidence=evidence,
            recommendations=[
                f"Escalate {item['rule_id']} ({item['severity']}) for human validation."
                for item in escalations
            ] or ["No escalations required."],
            confidence=1.0,
            engine=self.engine,
            metadata={"escalations": escalations, "canonical_count": len(canonical)},
        )


__all__ = ["PlanningAdapter", "CoordinationAdapter"]
