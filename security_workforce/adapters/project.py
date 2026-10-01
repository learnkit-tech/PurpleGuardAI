"""Project reconnaissance adapter (real, read-only execution).

Wraps PurpleGuard's project analyzer to map a target's languages,
framework, dependencies, and attack surface. Reconnaissance produces
**observations** (evidence), not vulnerability findings, so it never
manufactures canonical security findings.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

from ..contracts import Evidence, ValidationState
from .base import Adapter, AdapterOutput, InvalidTarget


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ProjectAdapter(Adapter):
    engine = "scanner.analyzer.project_analyzer.ProjectAnalyzer"

    def __init__(self, analyzer_factory=None) -> None:
        self._factory = analyzer_factory

    def _analyze(self, target: str) -> dict[str, Any]:
        if self._factory is not None:
            return self._factory(target).analyze()
        from scanner.analyzer.project_analyzer import ProjectAnalyzer

        return ProjectAnalyzer(target).analyze()

    def run(self, target: str | None, *, context: dict[str, Any] | None = None) -> AdapterOutput:
        if not target or not os.path.isdir(target):
            raise InvalidTarget(f"recon requires an existing target directory: {target!r}")

        data = self._analyze(target)

        surface = data.get("attack_surface", []) or []
        languages = data.get("languages", []) or []
        framework = data.get("framework")
        dependencies = data.get("dependencies", []) or []

        evidence = [
            Evidence(
                what_tested="project structure and attack surface",
                where_tested="<project>",
                what_happened=(
                    f"languages={languages} framework={framework} "
                    f"dependencies={len(dependencies)} attack_surface={len(surface)}"
                ),
                why_it_matters="Scope and attack surface bound the rest of the assessment.",
                reproduction=f"purpleguard project analysis of {target}",
                validation_state=ValidationState.UNVALIDATED.value,
                timestamp=_now(),
            ).to_dict()
        ]

        for entry in surface:
            evidence.append(
                Evidence(
                    what_tested="attack surface keyword",
                    where_tested=f"{entry.get('file')}",
                    what_happened=(
                        f"{entry.get('category')} ({entry.get('keyword')})"
                    ),
                    why_it_matters="An externally reachable surface is a candidate assessment area.",
                    validation_state=ValidationState.UNVALIDATED.value,
                    timestamp=_now(),
                ).to_dict()
            )

        recommendations = []
        if surface:
            categories = sorted({str(e.get("category")) for e in surface})
            recommendations.append(
                "Prioritize assessment of: " + ", ".join(categories) + "."
            )
        else:
            recommendations.append("No externally-reachable surface keywords were found.")

        return AdapterOutput(
            findings=[],
            evidence=evidence,
            recommendations=recommendations,
            confidence=1.0,
            engine=self.engine,
            metadata={
                "languages": languages,
                "framework": framework,
                "dependency_count": len(dependencies),
                "attack_surface_count": len(surface),
            },
        )


__all__ = ["ProjectAdapter"]
