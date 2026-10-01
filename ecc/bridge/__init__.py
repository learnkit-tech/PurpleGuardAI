"""ECC bridge — the only controlled surface between PurpleGuard and the ECC snapshot.

PurpleGuard code must depend on this package, never on files deeper in ``ecc/``.

    from ecc.bridge import EccBridge

    bridge = EccBridge()
    result = bridge.submit_task("agent.evaluate", input={"output": "tests passed ..."})

Execution is synchronous and results are structured; unavailable capabilities
return an explicit error (``ECC_UNAVAILABLE``), never a fabricated success.
"""

from __future__ import annotations

from typing import Any

from .client import EccBridge
from .contracts import (
    ECC_SOURCE_COMMIT,
    ECC_SOURCE_REPOSITORY,
    ErrorCode,
    StructuredError,
    Task,
    TaskResult,
    TaskStatus,
    deterministic_correlation_id,
    deterministic_task_id,
    make_task,
)
from .runtime import EccRuntime

__all__ = [
    "EccBridge",
    "EccRuntime",
    "Task",
    "TaskResult",
    "TaskStatus",
    "StructuredError",
    "ErrorCode",
    "ECC_SOURCE_COMMIT",
    "ECC_SOURCE_REPOSITORY",
    "deterministic_task_id",
    "deterministic_correlation_id",
    "make_task",
    "get_bridge",
    "submit_task",
]

_default_bridge: EccBridge | None = None


def get_bridge() -> EccBridge:
    """Return a process-wide default bridge (lazily created, no network)."""
    global _default_bridge
    if _default_bridge is None:
        _default_bridge = EccBridge()
    return _default_bridge


def submit_task(operation: str, **kwargs: Any) -> dict[str, Any]:
    """Convenience wrapper around the default bridge."""
    return get_bridge().submit_task(operation, **kwargs)
