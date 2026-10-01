"""The PurpleGuard-facing ECC bridge client.

Execution is **synchronous**: :meth:`EccBridge.submit_task` runs the operation
inline and returns a terminal result. There is no background queue and no
worker — only a small in-memory cache so ``get_task_status``/``get_task_result``
can retrieve the most recently submitted tasks. This is documented honestly
rather than presented as an asynchronous job system.
"""

from __future__ import annotations

from collections import OrderedDict
from typing import Any

from .contracts import (
    ECC_SOURCE_COMMIT,
    ErrorCode,
    TaskResult,
    TaskStatus,
    make_task,
)
from .runtime import EccRuntime

_DEFAULT_CACHE_SIZE = 64


class EccBridge:
    """Explicit adapter boundary between PurpleGuard and the ECC snapshot."""

    def __init__(self, runtime: EccRuntime | None = None, *, cache_size: int = _DEFAULT_CACHE_SIZE) -> None:
        self._runtime = runtime or EccRuntime()
        self._results: "OrderedDict[str, TaskResult]" = OrderedDict()
        self._cache_size = max(1, cache_size)

    @property
    def runtime(self) -> EccRuntime:
        return self._runtime

    # ---- submission ------------------------------------------------------

    def submit_task(
        self,
        operation: str,
        *,
        project_id: str = "purpleguard",
        input: dict[str, Any] | None = None,
        capability: str = "",
        timeout: float | None = None,
        idempotency_key: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Run one ECC operation synchronously and return a normalized result.

        Deterministic ids: pass ``idempotency_key`` to get the same ``task_id``
        and ``correlation_id`` for the same (project, operation, key).
        """
        if not isinstance(operation, str) or not operation.strip():
            raise ValueError("operation must be a non-empty string")

        task = make_task(
            operation.strip(),
            project_id=project_id,
            input=input,
            capability=capability,
            timeout=timeout,
            idempotency_key=idempotency_key,
            metadata=metadata,
        )
        result = self._runtime.execute(task)
        self._remember(result)
        return result.to_dict()

    # ---- retrieval (over the synchronous result cache) -------------------

    def get_task_status(self, task_id: str) -> dict[str, Any]:
        result = self._results.get(task_id)
        if result is None:
            return self._not_found(task_id)
        return {
            "task_id": result.task_id,
            "correlation_id": result.correlation_id,
            "operation": result.operation,
            "status": result.status,
            "synchronous": True,
        }

    def get_task_result(self, task_id: str) -> dict[str, Any]:
        result = self._results.get(task_id)
        if result is None:
            return self._not_found(task_id)
        return result.to_dict()

    # ---- introspection ---------------------------------------------------

    def status(self) -> dict[str, Any]:
        return self._runtime.status()

    def capabilities(self) -> list[dict[str, Any]]:
        status = self._runtime.status()
        ecc2_available = bool(status.get("ecc2", {}).get("available"))
        described = {
            "ecc.runtime.status": ("runtime", "available"),
            "ecc.snapshot.catalog": ("snapshot", "available"),
            "ecc.harness.describe": ("harness", "available"),
            "agent.evaluate": ("agent-capability", "available"),
            "integration.aura.trust_check": ("integration", "available"),
            "ecc2.session": ("control-plane", "available" if ecc2_available else "unavailable"),
        }
        return [
            {
                "operation": operation,
                "capability": capability,
                "availability": availability,
                "source_commit": ECC_SOURCE_COMMIT,
            }
            for operation, (capability, availability) in described.items()
        ]

    # ---- internals -------------------------------------------------------

    def _remember(self, result: TaskResult) -> None:
        self._results[result.task_id] = result
        self._results.move_to_end(result.task_id)
        while len(self._results) > self._cache_size:
            self._results.popitem(last=False)

    @staticmethod
    def _not_found(task_id: str) -> dict[str, Any]:
        return {
            "task_id": task_id,
            "correlation_id": None,
            "operation": None,
            "status": TaskStatus.REJECTED.value,
            "result": None,
            "errors": [
                {
                    "code": ErrorCode.ECC_TASK_NOT_FOUND.value,
                    "message": f"no cached result for task_id {task_id!r}",
                    "detail": {
                        "execution": "synchronous",
                        "hint": "results are cached in memory only; retrieval requires a prior submit in this process",
                    },
                }
            ],
            "metadata": {"synchronous": True},
        }
