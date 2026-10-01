"""ECC runtime adapter.

Executes only a small, verified allowlist of operations against the curated ECC
snapshot. It never shells out, never imports ECC internals into PurpleGuard
modules, and never mutates project files. Anything it cannot genuinely run is
reported as ``ECC_UNAVAILABLE`` rather than faked.

Two operations execute real extracted ECC code:

* ``agent.evaluate``   -> the ECC ``agent-self-evaluation`` 5-axis evaluator
* ``integration.aura.trust_check`` -> the ECC AURA trust-gate adapter

The ``ecc2`` Rust control plane is *not* built in this environment (no cargo /
rustc), so ``ecc2.*`` operations return ``ECC_UNAVAILABLE`` honestly.
"""

from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

from . import catalog, harness
from .contracts import (
    ECC_SOURCE_COMMIT,
    ErrorCode,
    Task,
    TaskResult,
    TaskStatus,
    completed,
    failed,
)

MAX_TEXT_CHARS = 200_000

_RUNTIME_OPERATIONS = (
    "ecc.runtime.status",
    "ecc.snapshot.catalog",
    "ecc.harness.describe",
    "agent.evaluate",
    "integration.aura.trust_check",
)

# ecc2 operations are recognized so we can answer them honestly, not so we can run them.
_ECC2_PREFIX = "ecc2."


class EccRuntime:
    """Synchronous adapter over the curated ECC snapshot."""

    def __init__(
        self,
        root: Path | str | None = None,
        *,
        fetch: Any = None,
        enable_network: bool = False,
    ) -> None:
        self.root = Path(root) if root is not None else Path(__file__).resolve().parents[1]
        # Optional injected HTTP fetcher for the AURA adapter (test seam / offline use).
        self._fetch = fetch
        self._enable_network = enable_network

    # ---- discovery -------------------------------------------------------

    def _ecc2_binary(self) -> str | None:
        on_path = shutil.which("ecc-tui")
        if on_path:
            return on_path
        for profile in ("release", "debug"):
            candidate = self.root / "ecc2" / "target" / profile / "ecc-tui"
            if candidate.is_file():
                return str(candidate)
        return None

    def status(self) -> dict[str, Any]:
        return {
            "source_commit": ECC_SOURCE_COMMIT,
            "snapshot_root": str(self.root),
            "operations": list(_RUNTIME_OPERATIONS),
            "ecc2": {
                "platform": sys.platform,
                "cargo": shutil.which("cargo"),
                "rustc": shutil.which("rustc"),
                "binary": self._ecc2_binary(),
                "available": self._ecc2_binary() is not None,
            },
        }

    # ---- dispatch --------------------------------------------------------

    def execute(self, task: Task) -> TaskResult:
        operation = task.operation

        try:
            if operation == "ecc.runtime.status":
                return completed(task, self.status())
            if operation == "ecc.snapshot.catalog":
                return completed(task, catalog.describe(self.root))
            if operation == "ecc.harness.describe":
                return completed(task, harness.describe(self.root))
            if operation == "agent.evaluate":
                return self._agent_evaluate(task)
            if operation == "integration.aura.trust_check":
                return self._aura_trust_check(task)
            if operation.startswith(_ECC2_PREFIX):
                return self._ecc2_unavailable(task)
        except Exception as exc:  # never leak a raw exception across the boundary
            return failed(
                task,
                ErrorCode.ECC_EXECUTION_ERROR,
                "unexpected error while executing ECC capability",
                detail={"operation": operation, "exception": type(exc).__name__},
            )

        return failed(
            task,
            ErrorCode.ECC_UNSUPPORTED_OPERATION,
            f"operation not supported by the ECC bridge: {operation!r}",
            status=TaskStatus.REJECTED,
            detail={"supported_operations": list(_RUNTIME_OPERATIONS)},
        )

    def _ecc2_unavailable(self, task: Task) -> TaskResult:
        return failed(
            task,
            ErrorCode.ECC_UNAVAILABLE,
            "ecc2 Rust control plane is not built/available in this environment",
            status=TaskStatus.UNAVAILABLE,
            detail={
                "cargo": shutil.which("cargo"),
                "rustc": shutil.which("rustc"),
                "binary": self._ecc2_binary(),
                "hint": "build ecc2/ (cargo build --release) or provide an ecc-tui binary, then retry",
            },
        )

    # ---- real ECC capabilities ------------------------------------------

    def _agent_evaluate(self, task: Task) -> TaskResult:
        output = task.input.get("output")
        task_text = task.input.get("task")

        if not isinstance(output, str) or not output.strip():
            return failed(
                task,
                ErrorCode.ECC_INVALID_TASK,
                "agent.evaluate requires a non-empty string input.output",
                status=TaskStatus.REJECTED,
            )
        if len(output) > MAX_TEXT_CHARS:
            return failed(
                task,
                ErrorCode.ECC_INVALID_TASK,
                f"input.output exceeds {MAX_TEXT_CHARS} characters",
                status=TaskStatus.REJECTED,
            )
        if task_text is not None and not isinstance(task_text, str):
            return failed(
                task,
                ErrorCode.ECC_INVALID_TASK,
                "input.task must be a string when provided",
                status=TaskStatus.REJECTED,
            )

        script = self.root / "skills" / "agent-self-evaluation" / "scripts" / "evaluate.py"
        module = self._load_module(script, "ecc_extracted_agent_evaluate")
        scores = module.evaluate(task_text, output)
        axes = [
            {
                "name": score.name,
                "score": score.score,
                "evidence": list(score.evidence),
                "improvement": score.improvement,
            }
            for score in scores
        ]
        overall = round(sum(score.score for score in scores) / len(scores), 3)
        return completed(
            task,
            {
                "axes": axes,
                "overall": overall,
                "report": module.format_report(scores),
            },
            metadata={"capability": "agent-self-evaluation", "source": "ecc/skills/agent-self-evaluation"},
        )

    def _aura_trust_check(self, task: Task) -> TaskResult:
        did = task.input.get("did")
        if not isinstance(did, str) or not did.startswith("did:"):
            return failed(
                task,
                ErrorCode.ECC_INVALID_TASK,
                "integration.aura.trust_check requires input.did starting with 'did:'",
                status=TaskStatus.REJECTED,
            )

        if self._fetch is None and not self._enable_network:
            return failed(
                task,
                ErrorCode.ECC_UNAVAILABLE,
                "AURA trust check disabled: no fetcher injected and network not explicitly enabled",
                status=TaskStatus.UNAVAILABLE,
                detail={"hint": "pass fetch=... or enable_network=True"},
            )

        adapter = self._load_module(
            self.root / "integrations" / "aura" / "adapter.py",
            "ecc_extracted_aura_adapter",
        )
        kwargs: dict[str, Any] = {}
        if self._fetch is not None:
            kwargs["_fetch"] = self._fetch
        try:
            verdict = adapter.aura_verdict(did, **kwargs)
        except ValueError as exc:
            return failed(
                task,
                ErrorCode.ECC_INVALID_TASK,
                "AURA adapter rejected the did",
                status=TaskStatus.REJECTED,
                detail={"error": str(exc)},
            )

        payload = verdict.as_dict()
        payload["reachable"] = verdict.reachable

        if not verdict.reachable:
            return failed(
                task,
                ErrorCode.ECC_UNAVAILABLE,
                "AURA endpoint unreachable; trust verdict is fail-closed 'unknown'",
                status=TaskStatus.UNAVAILABLE,
                detail={"verdict": payload},
            )
        return completed(
            task,
            payload,
            metadata={"capability": "aura-trust-gate", "source": "ecc/integrations/aura"},
        )

    # ---- helpers ---------------------------------------------------------

    @staticmethod
    def _load_module(path: Path, module_name: str) -> ModuleType:
        if not path.is_file():
            raise FileNotFoundError(f"ECC module not found in snapshot: {path.name}")
        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot load ECC module: {path.name}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
