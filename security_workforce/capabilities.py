"""Capability map: which agent executes, through which engine, how.

This is the single place that answers "is this capability genuinely
executable?" Each executable capability names a real adapter and the
PurpleGuard engine component it drives. A capability whose natural
engine primitive does not exist is marked ``executable=False`` with the
exact missing dependency, and the orchestrator reports it
``UNAVAILABLE`` - it is never silently faked.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Capability:
    agent_id: str
    operation: str
    adapter: str  # builder key resolved by the orchestrator
    engine: str
    executable: bool
    unavailable_reason: str = ""
    approval_required: bool = False


# Per-capability approval gate. Only active dynamic testing requires an
# explicit human approval flag; everything else is read-only.
APPROVAL_REQUIRED = {"e2e-runner"}

CAPABILITIES: dict[str, Capability] = {
    "security-reviewer": Capability(
        agent_id="security-reviewer",
        operation="security.review",
        adapter="scanner",
        engine="scanner.engine.SecurityScanner",
        executable=True,
    ),
    "database-reviewer": Capability(
        agent_id="database-reviewer",
        operation="security.review.database",
        adapter="database",
        engine="scanner.engine.SecurityScanner (injection rules)",
        executable=True,
    ),
    "mle-reviewer": Capability(
        agent_id="mle-reviewer",
        operation="security.review.ml",
        adapter="ml",
        engine="scanner.engine.SecurityScanner (deserialization/code-exec rules)",
        executable=True,
    ),
    "python-reviewer": Capability(
        agent_id="python-reviewer",
        operation="security.review.python",
        adapter="python",
        engine="scanner.engine.SecurityScanner (python files)",
        executable=True,
    ),
    "code-reviewer": Capability(
        agent_id="code-reviewer",
        operation="security.review.diff",
        adapter="hacker_static",
        engine="hacker.python_analyzer.PythonSecurityAnalyzer",
        executable=True,
    ),
    "code-explorer": Capability(
        agent_id="code-explorer",
        operation="security.recon",
        adapter="project",
        engine="scanner.analyzer.project_analyzer.ProjectAnalyzer",
        executable=True,
    ),
    "silent-failure-hunter": Capability(
        agent_id="silent-failure-hunter",
        operation="security.review.error-paths",
        adapter="errorpaths",
        engine="scanner.rules.silent_failure.SilentFailureRule (PG011)",
        executable=True,
    ),
    "comment-analyzer": Capability(
        agent_id="comment-analyzer",
        operation="security.review.comments",
        adapter="comments",
        engine="scanner.rules.secrets_in_comments.CommentSecretRule (PG012)",
        executable=True,
    ),
    "e2e-runner": Capability(
        agent_id="e2e-runner",
        operation="security.validate.e2e",
        adapter="dynamic",
        engine="hacker.orchestrator.PurpleGuardSecurityOrchestrator",
        executable=True,
        approval_required=True,
    ),
    "agent-evaluator": Capability(
        agent_id="agent-evaluator",
        operation="security.verify.result-quality",
        adapter="evaluation",
        engine="security_workforce.evaluation.evaluate_result",
        executable=True,
    ),
    "tdd-guide": Capability(
        agent_id="tdd-guide",
        operation="security.verify.regression",
        adapter="verification",
        engine="scanner.verification.engine.VerificationEngine",
        executable=True,
    ),
    "planner": Capability(
        agent_id="planner",
        operation="security.plan",
        adapter="planning",
        engine="security_workforce.orchestrator.WorkforceOrchestrator",
        executable=True,
    ),
    "chief-of-staff": Capability(
        agent_id="chief-of-staff",
        operation="security.coordinate",
        adapter="coordination",
        engine="security_workforce.orchestrator.WorkforceOrchestrator",
        executable=True,
    ),
    # ---- genuinely unavailable ---------------------------------------
    "architect": Capability(
        agent_id="architect",
        operation="security.assess.design",
        adapter="",
        engine="",
        executable=False,
        unavailable_reason="no design/threat-modeling engine exists in PurpleGuard",
    ),
    "spec-miner": Capability(
        agent_id="spec-miner",
        operation="security.recon.invariants",
        adapter="",
        engine="",
        executable=False,
        unavailable_reason="no behavioral-invariant extraction engine exists",
    ),
    "network-architect": Capability(
        agent_id="network-architect",
        operation="security.recon.network",
        adapter="",
        engine="",
        executable=False,
        unavailable_reason="no infrastructure/topology engine exists",
    ),
    "network-config-reviewer": Capability(
        agent_id="network-config-reviewer",
        operation="security.review.config",
        adapter="",
        engine="",
        executable=False,
        unavailable_reason="no config-file parsing engine (scanner runs on .py sources only)",
    ),
    "network-troubleshooter": Capability(
        agent_id="network-troubleshooter",
        operation="security.validate.network",
        adapter="",
        engine="",
        executable=False,
        unavailable_reason="no network diagnostic engine exists",
    ),
    "loop-operator": Capability(
        agent_id="loop-operator",
        operation="security.monitor",
        adapter="",
        engine="",
        executable=False,
        unavailable_reason=(
            "continuous-assessment scheduler is not implemented; a timer/sleep "
            "substitute is forbidden, so this stays unavailable"
        ),
    ),
    "harness-optimizer": Capability(
        agent_id="harness-optimizer",
        operation="security.optimize",
        adapter="",
        engine="",
        executable=False,
        unavailable_reason="no cost/throughput metrics engine exists",
    ),
}

# operation -> agent_id (routing)
OPERATION_ROUTING: dict[str, str] = {
    cap.operation: cap.agent_id for cap in CAPABILITIES.values()
}


def executable_capabilities() -> list[Capability]:
    return [cap for cap in CAPABILITIES.values() if cap.executable]


def unavailable_capabilities() -> list[Capability]:
    return [cap for cap in CAPABILITIES.values() if not cap.executable]


__all__ = [
    "APPROVAL_REQUIRED",
    "CAPABILITIES",
    "Capability",
    "OPERATION_ROUTING",
    "executable_capabilities",
    "unavailable_capabilities",
]
