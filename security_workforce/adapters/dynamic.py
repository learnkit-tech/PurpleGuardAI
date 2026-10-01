"""Dynamic validation adapter (real, authorized active testing).

Wraps PurpleGuard's security orchestrator: the Hacker discovers attack
paths, the planner selects a validator, and controlled harmless
payloads are sent to a PurpleGuard-owned local target that the engine
starts itself. Only behaviourally confirmed attacks become findings.

The engine requires the target to be a runnable local service (a
``run_server.py`` controlled launcher). When that is absent the
capability is honestly UNAVAILABLE rather than reported as a clean
result.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

from ..contracts import Evidence, ValidationState
from .base import Adapter, AdapterOutput, EngineUnavailable, InvalidTarget
from .hacker_static import CATEGORY_TO_RULE, RULE_NAME


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class DynamicValidationAdapter(Adapter):
    engine = "hacker.orchestrator.PurpleGuardSecurityOrchestrator"

    def __init__(self, orchestrator_factory=None) -> None:
        self._factory = orchestrator_factory

    def _orchestrator(self, target: str):
        if self._factory is not None:
            return self._factory(target)
        from hacker.orchestrator import PurpleGuardSecurityOrchestrator

        return PurpleGuardSecurityOrchestrator(target)

    @staticmethod
    def _sink_for(report_dict: dict[str, Any]) -> dict[str, dict[str, Any]]:
        sinks: dict[str, dict[str, Any]] = {}
        for path in report_dict.get("attack_paths", []) or []:
            for node in path.get("nodes", []) or []:
                if node.get("kind") == "SINK" and node.get("location"):
                    sinks[path.get("id")] = node["location"]
                    break
        return sinks

    def run(self, target: str | None, *, context: dict[str, Any] | None = None) -> AdapterOutput:
        if not target or not os.path.isdir(target):
            raise InvalidTarget(f"dynamic validation requires a target directory: {target!r}")

        if not os.path.exists(os.path.join(target, "run_server.py")):
            raise EngineUnavailable(
                "dynamic validation requires a controlled local target "
                "(run_server.py); none was found in the target"
            )

        orchestrator = self._orchestrator(target)

        try:
            report, report_dict = orchestrator.discover()
            plans = orchestrator.plan(report_dict)
            validations = orchestrator.validate(report_dict, plans)
        except EngineUnavailable:
            raise
        except (FileNotFoundError, RuntimeError) as exc:
            raise EngineUnavailable(f"dynamic validation engine could not run: {exc}") from exc

        sinks = self._sink_for(report_dict)

        findings: list[dict[str, Any]] = []
        evidence: list[dict[str, Any]] = []
        recommendations: set[str] = set()

        for validation in validations:
            if validation.get("validated") is not True:
                continue

            rule_id = CATEGORY_TO_RULE.get(validation.get("category", ""))
            location = sinks.get(validation.get("path_id"), {})

            file_path = location.get("file", "")
            line = location.get("line", 0)

            if rule_id:
                findings.append({
                    "id": rule_id,
                    "name": RULE_NAME.get(rule_id, validation.get("category", "")),
                    "severity": validation.get("severity", "HIGH"),
                    "category": validation.get("category", ""),
                    "file": file_path,
                    "line": line,
                    "code": location.get("code", ""),
                })

            relative = os.path.relpath(file_path, target) if file_path else "<target>"
            evidence.append(
                Evidence(
                    what_tested=f"dynamic validator {validation.get('validator', validation.get('path_id', ''))}",
                    where_tested=f"{relative}:{line}",
                    what_happened=str(validation.get("evidence", "")),
                    why_it_matters="A behaviourally confirmed attack is exploitable, not merely suspicious.",
                    reproduction=f"controlled payload: {validation.get('payload', '')}",
                    validation_state=ValidationState.UNVALIDATED.value,
                    timestamp=_now(),
                ).to_dict()
            )

            recommendations.add(
                f"Remediate confirmed [{rule_id or validation.get('category')}] at {relative}:{line}."
            )

        return AdapterOutput(
            findings=findings,
            evidence=evidence,
            recommendations=sorted(recommendations),
            confidence=1.0,
            engine=self.engine,
            metadata={
                "confirmed_attacks": len(findings),
                "planned_validations": len(plans),
                "files_analyzed": getattr(report, "files_analyzed", 0),
            },
        )


__all__ = ["DynamicValidationAdapter"]
