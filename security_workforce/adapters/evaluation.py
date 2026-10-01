"""Agent-result evaluation adapter (real execution).

Scores a prior workforce result with the native quality gate
(``security_workforce.evaluation.evaluate_result``) and returns the
verdict. It produces no vulnerability findings; it verifies the
*quality and authority* of a result the workforce already produced.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ..contracts import Evidence, ValidationState
from ..evaluation import evaluate_result
from .base import Adapter, AdapterOutput, InvalidTarget


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class EvaluationAdapter(Adapter):
    engine = "security_workforce.evaluation.evaluate_result"

    def __init__(self, store) -> None:
        self._store = store

    def run(self, target: str | None, *, context: dict[str, Any] | None = None) -> AdapterOutput:
        results = [r for r in self._store.list_results() if r.get("task_id")]
        if not results:
            raise InvalidTarget("no prior workforce result is available to evaluate")

        subject = results[-1]
        assessment = evaluate_result(subject)

        evidence = [
            Evidence(
                what_tested=f"agent result {subject.get('task_id')} from {subject.get('agent_id')}",
                where_tested="<workforce-store>",
                what_happened=(
                    f"overall={assessment['overall']} authoritative={assessment['authoritative']} "
                    f"requires_validation={assessment['requires_validation']} max_risk={assessment['max_risk']}"
                ),
                why_it_matters="A result is not authoritative merely because an agent produced it.",
                validation_state=ValidationState.UNVALIDATED.value,
                timestamp=_now(),
            ).to_dict()
        ]

        recommendations = []
        if assessment["requires_validation"]:
            recommendations.append(
                "High-risk findings require independent validation before they are authoritative."
            )
        if not assessment["authoritative"]:
            recommendations.append("Result is not authoritative; treat findings as requiring review.")

        return AdapterOutput(
            findings=[],
            evidence=evidence,
            recommendations=recommendations,
            confidence=float(assessment["overall"]),
            engine=self.engine,
            metadata={
                "evaluated_task_id": subject.get("task_id"),
                "evaluated_agent_id": subject.get("agent_id"),
                "assessment": assessment,
            },
        )


__all__ = ["EvaluationAdapter"]
