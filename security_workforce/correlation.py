"""Finding correlation / deduplication.

Multiple agents may report the same weakness. This layer produces **canonical**
findings so the same issue from several agents does not become several
authoritative findings. Provenance (which agents/tasks reported it) is preserved.

Nothing here is authoritative on its own: the canonical finding keeps a
``validation_state`` that starts ``unvalidated`` and only reaches
``corroborated``/``validated`` through evaluation/validation.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .contracts import ValidationState

_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def fingerprint(finding: dict[str, Any]) -> str:
    """Stable identity for a finding: rule + location.

    Deliberately excludes the ``code`` snippet: two independent engines
    may report slightly different source excerpts for the same sink, and
    the same weakness at the same location must remain one finding
    rather than two.
    """
    key = "|".join(
        str(finding.get(part, ""))
        for part in ("id", "file", "line")
    )
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]


def evidence_matches(finding: dict[str, Any], evidence: dict[str, Any]) -> bool:
    """True when an evidence entry describes this finding's location.

    Findings may carry an absolute path while evidence is relativized, so we
    match on line number plus file *basename*.
    """
    line = finding.get("line")
    if line is None:
        return False
    where = str(evidence.get("where_tested", ""))
    if not where.endswith(f":{line}"):
        return False
    relative = where.rsplit(":", 1)[0]
    return Path(relative).name == Path(str(finding.get("file", ""))).name


def _evidence_for(finding: dict[str, Any], result: dict[str, Any]) -> list[dict[str, Any]]:
    """Evidence entries belonging to a finding (matched by basename:line)."""
    return [
        ev for ev in result.get("evidence", ())
        if evidence_matches(finding, ev)
    ]


def correlate_results(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group findings across results into canonical findings."""
    groups: dict[str, dict[str, Any]] = {}

    for result in results:
        if result.get("status") != "completed":
            continue
        for finding in result.get("findings", ()):
            key = fingerprint(finding)
            entry = groups.setdefault(
                key,
                {
                    "fingerprint": key,
                    "rule_id": finding.get("id"),
                    "name": finding.get("name"),
                    "severity": finding.get("severity"),
                    "category": finding.get("category"),
                    "file": finding.get("file"),
                    "line": finding.get("line"),
                    "code": finding.get("code"),
                    "sources": [],
                    "evidence": [],
                    "validation_state": ValidationState.UNVALIDATED.value,
                    "remediation_state": "open",
                    "verification_state": "pending",
                    "first_seen": _now(),
                    "last_seen": _now(),
                },
            )
            entry["sources"].append(
                {
                    "agent_id": result.get("agent_id"),
                    "task_id": result.get("task_id"),
                    "correlation_id": result.get("correlation_id"),
                }
            )
            for ev in _evidence_for(finding, result):
                if ev not in entry["evidence"]:
                    entry["evidence"].append(ev)
            entry["last_seen"] = _now()

    for entry in groups.values():
        if len({source["agent_id"] for source in entry["sources"]}) >= 2:
            entry["validation_state"] = ValidationState.CORROBORATED.value

    return sorted(
        groups.values(),
        key=lambda item: (
            -_SEVERITY_RANK.get(str(item.get("severity", "")).upper(), 0),
            str(item.get("file", "")),
            int(item.get("line") or 0),
        ),
    )


def merge_canonical(
    existing: list[dict[str, Any]], incoming: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Merge newly correlated findings into existing canonical state."""
    by_key = {item.get("fingerprint"): dict(item) for item in existing}
    for new in incoming:
        key = new.get("fingerprint")
        if key in by_key:
            current = by_key[key]
            known = {
                (source.get("agent_id"), source.get("task_id"))
                for source in current.get("sources", [])
            }
            for source in new.get("sources", []):
                if (source.get("agent_id"), source.get("task_id")) not in known:
                    current.setdefault("sources", []).append(source)
            for ev in new.get("evidence", []):
                if ev not in current.setdefault("evidence", []):
                    current["evidence"].append(ev)
            if len({s.get("agent_id") for s in current.get("sources", [])}) >= 2:
                current["validation_state"] = ValidationState.CORROBORATED.value
            current["last_seen"] = _now()
        else:
            by_key[key] = dict(new)
    return list(by_key.values())


__all__ = ["fingerprint", "correlate_results", "merge_canonical", "evidence_matches"]
