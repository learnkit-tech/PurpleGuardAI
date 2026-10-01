"""Stable PurpleGuard-facing contracts for the ECC bridge.

Every value that crosses the ECC boundary is one of these types. PurpleGuard
application code must never receive a raw ECC object — only these contracts,
serialized with ``to_dict()``.

This module has no dependencies on ECC internals and no side effects.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

# Pinned provenance of the curated ECC snapshot vendored under ecc/.
ECC_SOURCE_REPOSITORY = "learnkit-tech/ECC"
ECC_SOURCE_COMMIT = "9c19aabe0f6506a4d0f47945e3f6cae59d7e4e7c"


class TaskStatus(str, Enum):
    """Lifecycle of a bridge task. Execution is synchronous, so a returned
    task is always already terminal (COMPLETED/FAILED/REJECTED/UNAVAILABLE/
    TIMED_OUT). ACCEPTED and RUNNING exist for contract completeness and for a
    future truly-async runtime; they are not emitted by the synchronous path."""

    ACCEPTED = "accepted"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    REJECTED = "rejected"
    TIMED_OUT = "timed_out"
    UNAVAILABLE = "unavailable"


class ErrorCode(str, Enum):
    """Explicit, stable error codes. A failure is never reported as success."""

    ECC_UNAVAILABLE = "ECC_UNAVAILABLE"
    ECC_UNSUPPORTED_OPERATION = "ECC_UNSUPPORTED_OPERATION"
    ECC_INVALID_TASK = "ECC_INVALID_TASK"
    ECC_MALFORMED_RESPONSE = "ECC_MALFORMED_RESPONSE"
    ECC_TIMEOUT = "ECC_TIMEOUT"
    ECC_REJECTED = "ECC_REJECTED"
    ECC_EXECUTION_ERROR = "ECC_EXECUTION_ERROR"
    ECC_TASK_NOT_FOUND = "ECC_TASK_NOT_FOUND"


@dataclass(frozen=True)
class StructuredError:
    """A machine-readable error. Never leaks raw ECC exception objects."""

    code: str
    message: str
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "message": self.message, "detail": dict(self.detail)}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _digest(*parts: str) -> str:
    joined = "\x1f".join(parts)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def deterministic_task_id(project_id: str, operation: str, key: str) -> str:
    """Deterministic id for an idempotent submission (same key -> same id)."""
    return "ecc-" + _digest("task", project_id, operation, key)[:24]


def deterministic_correlation_id(task_id: str) -> str:
    return "ecc-corr-" + _digest("corr", task_id)[:24]


@dataclass(frozen=True)
class Task:
    """An ECC-bound task. Built through :func:`make_task`."""

    task_id: str
    correlation_id: str
    project_id: str
    operation: str
    input: dict[str, Any] = field(default_factory=dict)
    capability: str = ""
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
            "capability": self.capability,
            "timeout": self.timeout,
            "idempotency_key": self.idempotency_key,
            "input": dict(self.input),
            "metadata": dict(self.metadata),
            "created_at": self.created_at,
        }


def make_task(
    operation: str,
    *,
    project_id: str = "purpleguard",
    input: dict[str, Any] | None = None,
    capability: str = "",
    timeout: float | None = None,
    idempotency_key: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> Task:
    """Build a task with deterministic ids when an idempotency key is given,
    otherwise a random nonce."""
    key = idempotency_key or secrets.token_hex(16)
    task_id = deterministic_task_id(project_id, operation, key)
    return Task(
        task_id=task_id,
        correlation_id=deterministic_correlation_id(task_id),
        project_id=project_id,
        operation=operation,
        input=dict(input or {}),
        capability=capability,
        timeout=timeout,
        idempotency_key=idempotency_key,
        metadata=dict(metadata or {}),
        created_at=_utc_now(),
    )


@dataclass(frozen=True)
class TaskResult:
    """Normalized result returned to PurpleGuard. Always serialized via dict."""

    task_id: str
    correlation_id: str
    status: str
    operation: str
    result: dict[str, Any] | None = None
    errors: tuple[StructuredError, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status == TaskStatus.COMPLETED.value and not self.errors

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "correlation_id": self.correlation_id,
            "operation": self.operation,
            "status": self.status,
            "result": dict(self.result) if self.result is not None else None,
            "errors": [error.to_dict() for error in self.errors],
            "metadata": dict(self.metadata),
        }


def completed(task: Task, result: dict[str, Any], metadata: dict[str, Any] | None = None) -> TaskResult:
    return TaskResult(
        task_id=task.task_id,
        correlation_id=task.correlation_id,
        status=TaskStatus.COMPLETED.value,
        operation=task.operation,
        result=result,
        metadata=dict(metadata or {}),
    )


def failed(
    task: Task,
    code: ErrorCode | str,
    message: str,
    *,
    status: TaskStatus | str = TaskStatus.FAILED,
    detail: dict[str, Any] | None = None,
    result: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
) -> TaskResult:
    code_value = code.value if isinstance(code, ErrorCode) else str(code)
    status_value = status.value if isinstance(status, TaskStatus) else str(status)
    return TaskResult(
        task_id=task.task_id,
        correlation_id=task.correlation_id,
        status=status_value,
        operation=task.operation,
        result=result,
        errors=(StructuredError(code=code_value, message=message, detail=dict(detail or {})),),
        metadata=dict(metadata or {}),
    )
