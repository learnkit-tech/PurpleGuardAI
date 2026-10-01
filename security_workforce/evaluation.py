"""Agent evaluation / quality gate.

Extracted from ECC's evaluation concept (``agent-self-evaluation`` /
``agent-evaluator``) and reimplemented natively for security results.

A finding does not become authoritative merely because an agent produced it.
``evaluate_result`` returns scores plus an ``authoritative`` decision and a
``requires_validation`` signal. Thresholds are explicit below — no hidden magic.
"""

from __future__ import annotations

from typing import Any

from .contracts import ValidationState
from .correlation import evidence_matches

# Documented thresholds (tune deliberately, not implicitly).
AUTHORITATIVE_MIN_EVIDENCE_QUALITY = 0.8
HIGH_RISK_SEVERITIES = {"HIGH", "CRITICAL"}


def _evidence_quality(result: dict[str, Any]) -> float:
    findings = result.get("findings", ())
    if not findings:
        return 1.0  # a clean result with no findings is trivially evidenced
    evidence = result.get("evidence", ())
    covered = 0
    for finding in findings:
        if any(evidence_matches(finding, ev) for ev in evidence):
            covered += 1
    return covered / len(findings)


def _reproducibility(result: dict[str, Any]) -> float:
    evidence = result.get("evidence", ())
    if not evidence:
        return 1.0 if not result.get("findings") else 0.0
    with_location = sum(
        1 for ev in evidence if ":" in str(ev.get("where_tested", ""))
    )
    return with_location / len(evidence)


def evaluate_result(result: dict[str, Any]) -> dict[str, Any]:
    status = result.get("status")
    findings = result.get("findings", ())
    sev = {str(f.get("severity", "")).upper() for f in findings}
    max_risk = "CRITICAL" if "CRITICAL" in sev else "HIGH" if "HIGH" in sev else "MEDIUM" if "MEDIUM" in sev else "LOW"

    axes = {
        "accuracy": 1.0 if status == "completed" else 0.0,
        "completeness": 1.0 if status == "completed" else 0.0,
        "evidence_quality": round(_evidence_quality(result), 3),
        "reproducibility": round(_reproducibility(result), 3),
        "clarity": 1.0 if result.get("recommendations") else 0.5,
        "actionability": 1.0 if result.get("recommendations") else 0.5,
        "confidence": float(result.get("confidence", 0.0)),
    }
    overall = round(sum(axes.values()) / len(axes), 3)

    high_risk = bool(sev & HIGH_RISK_SEVERITIES)
    requires_validation = high_risk
    authoritative = (
        status == "completed"
        and axes["evidence_quality"] >= AUTHORITATIVE_MIN_EVIDENCE_QUALITY
        and not high_risk
    )

    return {
        "axes": axes,
        "max_risk": max_risk,
        "overall": overall,
        "authoritative": authoritative,
        "requires_validation": requires_validation,
        "validation_state": result.get("metadata", {}).get("validation_state", ValidationState.UNVALIDATED.value),
        "thresholds": {
            "authoritative_min_evidence_quality": AUTHORITATIVE_MIN_EVIDENCE_QUALITY,
            "high_risk_requires_validation": True,
        },
        "provenance": {"adapted_from": "ecc/skills/agent-self-evaluation", "native": True},
    }


__all__ = ["evaluate_result"]
