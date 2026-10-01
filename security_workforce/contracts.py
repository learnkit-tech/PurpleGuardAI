"""PurpleGuard Security Workforce — core contracts.

PurpleGuard-native. These are the only shapes that cross the workforce boundary:
agent definitions, tasks, evidence, and normalized results. An unverified agent
claim never becomes authoritative security state; callers must consult the
evaluation/validation layers (see evaluation.py and the existing Phase 4 loop).

Provenance of the agent knowledge adapted here: ECC commit
``9c19aabe0f6506a4d0f47945e3f6cae59d7e4e7c`` (``learnkit-tech/ECC``). See
``security_workforce/registry/agents.json`` and ``docs/ECC_CAPABILITY_MAP.md``.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

ECC_SOURCE_REPOSITORY = "learnkit-tech/ECC"
ECC_SOURCE_COMMIT = "9c19aabe0f6506a4d0f47945e3f6cae59d7e4e7c"


class TaskStatus(str, Enum):
    CREATED = "created"
    ACCEPTED = "accepted"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    REJECTED = "rejected"
    TIMED_OUT = "timed_out"
    UNAVAILABLE = "unavailable"


class AgentStatus(str, Enum):
    COMPLETED = "completed"
    FAILED = "failed"
    REJECTED = "rejected"
    UNAVAILABLE = "unavailable"


class Permission(str, Enum):
    OBSERVE = "observe"
    ANALYZE = "analyze"
    VALIDATE = "validate"
    PROPOSE = "propose"
    MODIFY = "modify"  # never granted to an agent; reserved for the human gate
    VERIFY = "verify"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ValidationState(str, Enum):
    UNVALIDATED = "unvalidated"
    CORROBORATED = "corroborated"
    VALIDATED = "validated"
    REFUTED = "refuted"


class CapabilityState(str, Enum):
    """Honest lifecycle state of a capability.

    DISCOVERED  - present in the source material / audit.
    DEFINED     - a registry contract exists, but no real execution.
    AVAILABLE   - a real engine adapter can execute it.
    RUNNING     - execution in flight (transient).
    COMPLETED   - executed against an authorized target with a real result.
    FAILED      - execution was attempted and failed.
    REJECTED    - refused (permission, approval, or invalid task).
    UNAVAILABLE - the required engine primitive is genuinely missing.
    """

    DISCOVERED = "DISCOVERED"
    DEFINED = "DEFINED"
    AVAILABLE = "AVAILABLE"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    REJECTED = "REJECTED"
    UNAVAILABLE = "UNAVAILABLE"


class AgentStatusReason(str, Enum):  # structured error codes
    ECC_UNAVAILABLE = "ECC_UNAVAILABLE"
    ENGINE_UNAVAILABLE = "ENGINE_UNAVAILABLE"
    UNSUPPORTED_OPERATION = "UNSUPPORTED_OPERATION"
    INVALID_TASK = "INVALID_TASK"
    MALFORMED_RESULT = "MALFORMED_RESULT"
    EXECUTION_ERROR = "EXECUTION_ERROR"
    REJECTED = "REJECTED"
    TIMEOUT = "TIMEOUT"
    TASK_NOT_FOUND = "TASK_NOT_FOUND"


@dataclass(frozen=True)
class StructuredError:
    code: str
    message: str
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "message": self.message, "detail": dict(self.detail)}


@dataclass(frozen=True)
class Evidence:
    """Evidence-first model. A finding without evidence is not authoritative."""

    what_tested: str
    where_tested: str
    what_happened: str
    why_it_matters: str = ""
    reproduction: str = ""
    artifacts: tuple[str, ...] = ()
    validation_state: str = ValidationState.UNVALIDATED.value
    timestamp: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "what_tested": self.what_tested,
            "where_tested": self.where_tested,
            "what_happened": self.what_happened,
            "why_it_matters": self.why_it_matters,
            "reproduction": self.reproduction,
            "artifacts": list(self.artifacts),
            "validation_state": self.validation_state,
            "timestamp": self.timestamp or _utc_now(),
        }


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _digest(*parts: str) -> str:
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()


def deterministic_task_id(project_id: str, operation: str, key: str) -> str:
    return "pgtask-" + _digest("task", project_id, operation, key)[:24]


def deterministic_correlation_id(task_id: str) -> str:
    return "pgcorr-" + _digest("corr", task_id)[:24]


@dataclass(frozen=True)
class Task:
    task_id: str
    correlation_id: str
    project_id: str
    operation: str
    input: dict[str, Any] = field(default_factory=dict)
    playbook: str = ""
    timeout: float | None = None
    idempotency_key: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "correlation_id": self.correlation_id,
            "project_id": self.project_id,
            "operation": self.operation,
            "input": dict(self.input),
            "playbook": self.playbook,
            "timeout": self.timeout,
            "idempotency_key": self.idempotency_key,
            "metadata": dict(self.metadata),
            "created_at": self.created_at,
        }


def make_task(
    operation: str,
    *,
    project_id: str = "purpleguard",
    input: dict[str, Any] | None = None,
    playbook: str = "",
    timeout: float | None = None,
    idempotency_key: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> Task:
    key = idempotency_key or secrets.token_hex(16)
    task_id = deterministic_task_id(project_id, operation, key)
    return Task(
        task_id=task_id,
        correlation_id=deterministic_correlation_id(task_id),
        project_id=project_id,
        operation=operation,
        input=dict(input or {}),
        playbook=playbook,
        timeout=timeout,
        idempotency_key=idempotency_key,
        metadata=dict(metadata or {}),
        created_at=_utc_now(),
    )


@dataclass(frozen=True)
class AgentSpec:
    """A registry entry — a PurpleGuard security agent definition."""

    agent_id: str
    name: str
    role: str
    mission: str
    capabilities: tuple[str, ...] = ()
    knowledge_domains: tuple[str, ...] = ()
    skills: tuple[str, ...] = ()
    rules: tuple[str, ...] = ()
    tools: tuple[str, ...] = ()
    inputs: tuple[str, ...] = ()
    outputs: tuple[str, ...] = ()
    required_evidence: tuple[str, ...] = ()
    permissions: frozenset[str] = frozenset()
    approval_required: bool = True
    escalation_conditions: tuple[str, ...] = ()
    dependencies: tuple[str, ...] = ()
    compatible_tasks: tuple[str, ...] = ()
    verification_requirements: tuple[str, ...] = ()
    risk_level: str = RiskLevel.MEDIUM.value
    enabled: bool = False
    implementation: str = "defined_only"  # "available" | "defined_only"
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "role": self.role,
            "mission": self.mission,
            "capabilities": list(self.capabilities),
            "knowledge_domains": list(self.knowledge_domains),
            "skills": list(self.skills),
            "rules": list(self.rules),
            "tools": list(self.tools),
            "inputs": list(self.inputs),
            "outputs": list(self.outputs),
            "required_evidence": list(self.required_evidence),
            "permissions": sorted(self.permissions),
            "approval_required": self.approval_required,
            "escalation_conditions": list(self.escalation_conditions),
            "dependencies": list(self.dependencies),
            "compatible_tasks": list(self.compatible_tasks),
            "verification_requirements": list(self.verification_requirements),
            "risk_level": self.risk_level,
            "enabled": self.enabled,
            "implementation": self.implementation,
            "provenance": dict(self.provenance),
        }


@dataclass(frozen=True)
class AgentResult:
    agent_id: str
    task_id: str
    correlation_id: str
    role: str
    status: str
    findings: tuple[dict[str, Any], ...] = ()
    evidence: tuple[dict[str, Any], ...] = ()
    recommendations: tuple[str, ...] = ()
    confidence: float = 0.0
    errors: tuple[StructuredError, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status == AgentStatus.COMPLETED.value and not self.errors

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "task_id": self.task_id,
            "correlation_id": self.correlation_id,
            "role": self.role,
            "status": self.status,
            "findings": [dict(item) for item in self.findings],
            "evidence": [dict(item) for item in self.evidence],
            "recommendations": list(self.recommendations),
            "confidence": self.confidence,
            "errors": [error.to_dict() for error in self.errors],
            "metadata": dict(self.metadata),
        }
