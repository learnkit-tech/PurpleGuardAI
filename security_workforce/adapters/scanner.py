"""Adapter to PurpleGuard's static scanner (real, read-only execution).

Adapters are the seam between a workforce agent and a PurpleGuard tool.
They are where "observe/analyze" permissions become concrete, and they
are the only place PurpleGuard tooling is imported.

The same engine backs several focused agents: a rule filter turns one
adapter into the database reviewer (injection rules), the ML reviewer
(deserialization/code-execution rules), the error-path hunter (PG011,
an optional engine rule), and so on. Filtering never invents a finding:
it narrows the real scanner's output.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from ..contracts import Evidence, ValidationState
from .base import Adapter, AdapterOutput, InvalidTarget


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _default_scanner(target: str, rules=None):
    from scanner.engine import SecurityScanner

    if rules is None:
        return SecurityScanner(target)
    return SecurityScanner(target, rules=rules)


def _relative(target: str, file_path: str) -> str:
    try:
        return str(Path(file_path).relative_to(target))
    except (ValueError, OSError):
        return file_path


class ScannerAdapter(Adapter):
    engine = "scanner.engine.SecurityScanner"

    def __init__(
        self,
        scanner_factory: Callable[[str], Any] | None = None,
        *,
        rule_ids: tuple[str, ...] | None = None,
        rules: list[Any] | None = None,
        suffixes: tuple[str, ...] = (".py",),
    ) -> None:
        self._factory = scanner_factory
        self._rule_ids = frozenset(rule_ids) if rule_ids else None
        self._rules = rules
        self._suffixes = suffixes

    def _build(self, target: str) -> Any:
        if self._factory is not None:
            return self._factory(target)
        return _default_scanner(target, self._rules)

    def review(self, target: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
        output = self.run(target)
        return output.findings, output.evidence, output.recommendations

    def run(self, target: str | None, *, context: dict[str, Any] | None = None) -> AdapterOutput:
        if not target or not os.path.isdir(target):
            raise InvalidTarget(f"scanner requires an existing target directory: {target!r}")

        scanner = self._build(target)
        raw = list(scanner.scan())

        if self._rule_ids is not None:
            raw = [item for item in raw if item.get("id") in self._rule_ids]

        if self._suffixes:
            raw = [
                item for item in raw
                if str(item.get("file", "")).endswith(self._suffixes)
            ]

        findings: list[dict[str, Any]] = []
        evidence: list[dict[str, Any]] = []
        recommendations: set[str] = set()

        for finding in raw:
            findings.append(dict(finding))
            relative = _relative(target, str(finding.get("file", "")))
            line = finding.get("line")
            evidence.append(
                Evidence(
                    what_tested=f"static rule {finding.get('id')}",
                    where_tested=f"{relative}:{line}",
                    what_happened=f"{finding.get('name')} detected: {finding.get('code')}",
                    why_it_matters=f"{finding.get('severity')} severity, {finding.get('category')}",
                    reproduction=f"purpleguard static review of {target}",
                    artifacts=(str(finding.get("file", "")),),
                    validation_state=ValidationState.UNVALIDATED.value,
                    timestamp=_now(),
                ).to_dict()
            )
            location = f"{relative}:{line}" if line is not None else relative
            recommendations.add(
                f"[{finding.get('severity')}] {finding.get('name')} at {location} — review and remediate."
            )

        return AdapterOutput(
            findings=findings,
            evidence=evidence,
            recommendations=sorted(recommendations),
            confidence=1.0,  # deterministic static analysis over a real target
            engine=self.engine,
            metadata={
                "rule_ids": sorted(self._rule_ids) if self._rule_ids else None,
                "suffixes": list(self._suffixes),
                "finding_count": len(findings),
            },
        )


__all__ = ["ScannerAdapter"]
