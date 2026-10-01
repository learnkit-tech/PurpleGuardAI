"""Hacker static attack-path adapter (real, read-only execution).

A second, independently implemented engine: PurpleGuard's Hacker
analyzer (``hacker.python_analyzer``) performs source/sink taint
tracking and derives attack paths, rather than the scanner's per-rule
AST pattern matching.

Running this *in addition to* the scanner is what makes independent
validation genuine: two different engines observe the same weakness at
the same location from the same source, so correlation can mark the
canonical finding ``corroborated`` - and a single engine alone can
never do that.

Attack-path categories are normalized to the scanner's stable rule ids
(``CODE_EXECUTION`` -> ``PG002`` and so on) so both engines agree on a
finding's identity. The mapping only labels an independently observed
weakness; it never creates one.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

from ..contracts import Evidence, ValidationState
from .base import Adapter, AdapterOutput, InvalidTarget

CATEGORY_TO_RULE = {
    "CODE_EXECUTION": "PG002",
    "COMMAND_INJECTION": "PG005",
    "SQL_INJECTION": "PG004",
    "PATH_TRAVERSAL": "PG006",
    "XSS": "PG007",
    "OPEN_REDIRECT": "PG008",
    "SSRF": "PG009",
    "DESERIALIZATION": "PG010",
}

RULE_NAME = {
    "PG002": "Dangerous eval()",
    "PG004": "SQL Injection",
    "PG005": "Command Injection",
    "PG006": "Path Traversal",
    "PG007": "Cross-Site Scripting",
    "PG008": "Open Redirect",
    "PG009": "SSRF",
    "PG010": "Insecure Deserialization",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sink_location(path: Any) -> tuple[str, int, str]:
    nodes = getattr(path, "nodes", []) or []
    for node in nodes:
        if getattr(node, "kind", None) == "SINK" and getattr(node, "location", None):
            loc = node.location
            return loc.file, int(loc.line), loc.code or ""
    return "", 0, ""


class HackerStaticAdapter(Adapter):
    engine = "hacker.python_analyzer.PythonSecurityAnalyzer"

    def __init__(self, hacker_factory=None) -> None:
        self._factory = hacker_factory

    def _hack(self, target: str):
        if self._factory is not None:
            return self._factory(target).hack()
        from hacker.engine import PurpleGuardHacker

        return PurpleGuardHacker(target).hack()

    def run(self, target: str | None, *, context: dict[str, Any] | None = None) -> AdapterOutput:
        if not target or not os.path.isdir(target):
            raise InvalidTarget(f"attack-path analysis requires a target directory: {target!r}")

        report = self._hack(target)

        findings: list[dict[str, Any]] = []
        evidence: list[dict[str, Any]] = []
        recommendations: set[str] = set()

        for path in getattr(report, "attack_paths", []) or []:
            rule_id = CATEGORY_TO_RULE.get(getattr(path, "category", ""))
            if not rule_id:
                continue

            file_path, line, code = _sink_location(path)
            if not file_path:
                continue

            findings.append({
                "id": rule_id,
                "name": RULE_NAME.get(rule_id, getattr(path, "title", "")),
                "severity": getattr(path, "severity", "MEDIUM"),
                "category": getattr(path, "category", ""),
                "file": file_path,
                "line": line,
                "code": code,
            })

            relative = os.path.relpath(file_path, target)
            evidence.append(
                Evidence(
                    what_tested=f"independent attack path {getattr(path, 'id', '')}",
                    where_tested=f"{relative}:{line}",
                    what_happened=(
                        f"{getattr(path, 'title', '')} "
                        f"(confidence {getattr(path, 'confidence', 0.0)}, status {getattr(path, 'status', '')})"
                    ),
                    why_it_matters=f"{getattr(path, 'impact', '')}",
                    reproduction=f"purpleguard hacker analysis of {target}",
                    validation_state=ValidationState.UNVALIDATED.value,
                    timestamp=_now(),
                ).to_dict()
            )

            recommendations.add(
                f"Independently confirmed [{rule_id}] {RULE_NAME.get(rule_id, '')} at {relative}:{line}."
            )

        return AdapterOutput(
            findings=findings,
            evidence=evidence,
            recommendations=sorted(recommendations),
            confidence=1.0,
            engine=self.engine,
            metadata={
                "files_analyzed": getattr(report, "files_analyzed", 0),
                "attack_path_count": len(getattr(report, "attack_paths", []) or []),
            },
        )


__all__ = ["HackerStaticAdapter", "CATEGORY_TO_RULE"]
