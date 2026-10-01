"""Re-test verification adapter (real execution).

Runs the target's automated test suite through PurpleGuard's
verification engine, the same engine the remediation loop uses for its
test layer. It produces no vulnerability findings; it returns real
test evidence. This is one of the three independent verification
layers (static rescan, tests, adversarial re-attack).
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

from ..contracts import Evidence, ValidationState
from .base import Adapter, AdapterOutput, InvalidTarget


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class VerificationAdapter(Adapter):
    engine = "scanner.verification.engine.VerificationEngine"

    def __init__(self, engine_factory=None) -> None:
        self._factory = engine_factory

    def _engine(self):
        if self._factory is not None:
            return self._factory()
        from scanner.verification.engine import VerificationEngine

        return VerificationEngine()

    def run(self, target: str | None, *, context: dict[str, Any] | None = None) -> AdapterOutput:
        if not target or not os.path.isdir(target):
            raise InvalidTarget(f"re-test requires an existing target directory: {target!r}")

        result = self._engine().verify_tests(target)
        passed = bool(result.get("passed"))

        evidence = [
            Evidence(
                what_tested="target automated test suite",
                where_tested=str(target),
                what_happened=f"tests_passed={passed} return_code={result.get('return_code')}",
                why_it_matters="A remediation is not verified unless the project's own tests still pass.",
                reproduction="python -m pytest",
                validation_state=ValidationState.UNVALIDATED.value,
                timestamp=_now(),
            ).to_dict()
        ]

        recommendations = [
            "Project tests pass after the change."
            if passed
            else "Project tests do not pass; do not mark the change verified."
        ]

        return AdapterOutput(
            findings=[],
            evidence=evidence,
            recommendations=recommendations,
            confidence=1.0,
            engine=self.engine,
            metadata={
                "tests_passed": passed,
                "return_code": result.get("return_code"),
            },
        )


__all__ = ["VerificationAdapter"]
