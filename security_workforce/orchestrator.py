"""PurpleGuard Security Workforce orchestrator.

Coordinates the workforce: route -> authorize -> execute -> evaluate ->
correlate -> persist. It never runs every agent per call, never mutates
source, and never turns an unvalidated claim into authoritative security
state.

Every executable capability is backed by a real adapter (see
``capabilities.py`` and ``adapters/``). Capabilities with no engine
primitive are reported ``UNAVAILABLE`` with the exact reason. Continuous
scheduling is a separate, deliberately unimplemented layer; it is never
faked with sleeps or timers.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from . import correlation, evaluation
from .agents import EngineAgent
from .capabilities import CAPABILITIES, OPERATION_ROUTING, Capability
from .context import ContextBuilder
from .contracts import (
    AgentResult,
    AgentStatus,
    AgentStatusReason,
    CapabilityState,
    StructuredError,
    Task,
    make_task,
)
from .playbooks import get_playbook
from .registry import load_registry, validate_registry
from .store import WorkforceStore


class WorkforceOrchestrator:
    def __init__(
        self,
        *,
        registry_path: str | Path | None = None,
        store: WorkforceStore | None = None,
        adapter: Any = None,
        agents: dict[str, Any] | None = None,
        context_builder: ContextBuilder | None = None,
    ) -> None:
        self._registry = load_registry(registry_path)
        self._store = store or WorkforceStore()
        self._context = context_builder or ContextBuilder(self._store)
        self._injected_adapter = adapter
        self._agents: dict[str, Any] = self._build_agents()
        if agents:
            # Explicit overrides win, including ``None`` to simulate a
            # missing/unavailable adapter.
            self._agents.update(agents)

    # ---- adapter / agent construction -----------------------------------

    def _build_agents(self) -> dict[str, Any]:
        agents: dict[str, Any] = {}
        for cap in CAPABILITIES.values():
            if not cap.executable:
                continue
            adapter = self._build_adapter(cap)
            spec = self._registry.get(cap.agent_id)
            role = spec.role if spec else "orchestration"
            permissions = spec.permissions if spec else frozenset()
            agents[cap.agent_id] = EngineAgent(
                cap.agent_id, role, permissions, adapter, engine=cap.engine,
            )
        return agents

    def _build_adapter(self, cap: Capability) -> Any:
        key = cap.adapter
        if key == "scanner":
            if self._injected_adapter is not None:
                return self._injected_adapter
            return _scanner()
        if key == "database":
            return _scanner(rule_ids=("PG004", "PG005"))
        if key == "ml":
            return _scanner(rule_ids=("PG010", "PG002"))
        if key == "python":
            return _scanner()
        if key == "errorpaths":
            return _scanner(rules=[_optional_rule("SilentFailureRule")])
        if key == "comments":
            return _scanner(rules=[_optional_rule("CommentSecretRule")])
        if key == "project":
            return _project()
        if key == "hacker_static":
            return _hacker_static()
        if key == "dynamic":
            return _dynamic()
        if key == "evaluation":
            return _evaluation(self._store)
        if key == "verification":
            return _verification()
        if key == "planning":
            return _planning(self._registry)
        if key == "coordination":
            return _coordination(self._store)
        raise ValueError(f"unknown adapter key {key!r}")

    # ---- discovery -------------------------------------------------------

    @property
    def store(self) -> WorkforceStore:
        """The workforce's persistence seam (for handoff/consumers)."""
        return self._store

    def validate(self) -> list[str]:
        return validate_registry()

    def list_agents(self) -> list[dict[str, Any]]:
        return [spec.to_dict() for spec in self._registry.values()]

    def get_agent(self, agent_id: str) -> dict[str, Any] | None:
        spec = self._registry.get(agent_id)
        return spec.to_dict() if spec else None

    def select(self, operation: str) -> dict[str, Any] | None:
        spec = self._registry.get(OPERATION_ROUTING.get(operation, ""))
        return spec.to_dict() if spec else None

    def playbook(self, playbook_id: str) -> dict[str, Any] | None:
        return get_playbook(playbook_id)

    def capabilities(self) -> list[dict[str, Any]]:
        """Honest capability states: AVAILABLE / DEFINED / UNAVAILABLE."""
        out = []
        for cap in CAPABILITIES.values():
            spec = self._registry.get(cap.agent_id)
            if not cap.executable:
                state = CapabilityState.UNAVAILABLE
            elif spec is not None and spec.implementation == "available":
                state = CapabilityState.AVAILABLE
            else:
                state = CapabilityState.DEFINED
            out.append({
                "agent_id": cap.agent_id,
                "operation": cap.operation,
                "engine": cap.engine,
                "executable": cap.executable,
                "state": state.value,
                "unavailable_reason": cap.unavailable_reason,
                "approval_required": cap.approval_required,
            })
        return out

    # ---- execution -------------------------------------------------------

    def run(
        self,
        operation: str,
        *,
        target: str | None = None,
        project_id: str = "purpleguard",
        idempotency_key: str | None = None,
        required_permissions: tuple[str, ...] | None = None,
        playbook: str = "",
        approved: bool = False,
    ) -> dict[str, Any]:
        task, result, assessment = self._dispatch(
            operation,
            target=target,
            project_id=project_id,
            idempotency_key=idempotency_key,
            required_permissions=required_permissions,
            playbook=playbook,
            approved=approved,
        )
        return self._finalize(task, result, assessment)

    def assess(
        self,
        target: str,
        *,
        agents: list[str] | None = None,
        project_id: str = "purpleguard",
        idempotency_key: str | None = None,
        approved: bool = False,
        playbook: str = "security.static_review",
    ) -> dict[str, Any]:
        """Run a genuine multi-agent pass and correlate the results.

        ``agents`` is an ordered list of agent ids; defaults to the
        discovery + independent-validation pair used by Phase 3.
        """
        if agents is None:
            agents = ["security-reviewer", "code-reviewer"]

        tasks: list[Task] = []
        results: list[AgentResult] = []
        assessments: list[dict[str, Any]] = []

        for agent_id in agents:
            cap = CAPABILITIES.get(agent_id)
            if cap is None or not cap.executable:
                continue
            key = idempotency_key
            task, result, assessment = self._dispatch(
                cap.operation,
                target=target,
                project_id=project_id,
                idempotency_key=f"{key}:{agent_id}" if key else None,
                playbook=playbook,
                approved=approved,
            )
            tasks.append(task)
            results.append(result)
            assessments.append(assessment)

        return self._finalize_many(
            tasks, results, assessments, target=target, project_id=project_id, playbook=playbook,
        )

    # ---- retrieval -------------------------------------------------------

    def result(self, task_id: str) -> dict[str, Any] | None:
        return self._store.get_result(task_id)

    def results(self) -> list[dict[str, Any]]:
        return self._store.list_results()

    def canonical_findings(self) -> list[dict[str, Any]]:
        return self._store.list_canonical_findings()

    # ---- internals -------------------------------------------------------

    def _dispatch(
        self,
        operation: str,
        *,
        target: str | None,
        project_id: str,
        idempotency_key: str | None,
        required_permissions: tuple[str, ...] | None = None,
        playbook: str = "",
        approved: bool = False,
    ) -> tuple[Task, AgentResult, dict[str, Any]]:
        task = make_task(
            operation,
            project_id=project_id,
            input={"target": target},
            playbook=playbook,
            idempotency_key=idempotency_key,
        )

        spec = self._registry.get(OPERATION_ROUTING.get(operation, ""))
        if spec is None:
            return (
                task,
                self._synthetic(
                    task, "unrouted", "orchestration", AgentStatus.REJECTED,
                    AgentStatusReason.UNSUPPORTED_OPERATION,
                    f"no agent routes operation {operation!r}",
                    {"routed_operations": sorted(OPERATION_ROUTING)},
                ),
                {},
            )

        cap = CAPABILITIES.get(spec.agent_id)
        if cap is not None and not cap.executable:
            return (
                task,
                self._synthetic(
                    task, spec.agent_id, spec.role, AgentStatus.UNAVAILABLE,
                    AgentStatusReason.ENGINE_UNAVAILABLE,
                    f"capability {spec.agent_id!r} has no engine path",
                    {"unavailable_reason": cap.unavailable_reason, "operation": cap.operation},
                ),
                {},
            )

        required = (
            frozenset(required_permissions)
            if required_permissions is not None
            else frozenset(spec.permissions)
        )
        missing = sorted(set(required) - set(spec.permissions))
        if missing:
            return (
                task,
                self._synthetic(
                    task, spec.agent_id, spec.role, AgentStatus.REJECTED,
                    AgentStatusReason.REJECTED,
                    f"agent {spec.agent_id!r} lacks required permissions",
                    {"missing_permissions": missing, "granted": sorted(spec.permissions)},
                ),
                {},
            )

        if cap is not None and cap.approval_required and not approved:
            return (
                task,
                self._synthetic(
                    task, spec.agent_id, spec.role, AgentStatus.REJECTED,
                    AgentStatusReason.REJECTED,
                    f"operation {operation!r} requires explicit approval",
                    {"approval_required": True, "operation": cap.operation},
                ),
                {},
            )

        agent = self._agents.get(spec.agent_id)
        if agent is None:
            return (
                task,
                self._synthetic(
                    task, spec.agent_id, spec.role, AgentStatus.UNAVAILABLE,
                    AgentStatusReason.ECC_UNAVAILABLE,
                    f"agent {spec.agent_id!r} has no implemented adapter",
                    {"implementation": spec.implementation},
                ),
                {},
            )

        context = self._context.build(
            project_id=project_id, target=target, task=task.to_dict(),
            agent_id=spec.agent_id, policies={"approved": approved},
        )
        try:
            result = agent.execute(task, target=target, context=context.for_agent(spec.agent_id))
        except Exception as exc:  # normalize any adapter failure
            result = self._synthetic(
                task, spec.agent_id, spec.role, AgentStatus.FAILED,
                AgentStatusReason.EXECUTION_ERROR,
                f"agent {spec.agent_id!r} raised during execution",
                {"exception": type(exc).__name__},
            )
        if not isinstance(result, AgentResult):
            result = self._synthetic(
                task, spec.agent_id, spec.role, AgentStatus.FAILED,
                AgentStatusReason.MALFORMED_RESULT,
                f"agent {spec.agent_id!r} returned a non-normalized result",
                {"returned_type": type(result).__name__},
            )
        return task, result, evaluation.evaluate_result(result.to_dict())

    def _finalize(self, task: Task, result: AgentResult, assessment: dict[str, Any] | None = None) -> dict[str, Any]:
        payload = result.to_dict()

        assessment = assessment if assessment else evaluation.evaluate_result(payload)
        new_canonical = correlation.correlate_results([payload])
        merged = correlation.merge_canonical(self._store.list_canonical_findings(), new_canonical)
        merged_by_key = {item["fingerprint"]: item for item in merged}
        canonical_for_task = [
            merged_by_key.get(item["fingerprint"], item) for item in new_canonical
        ]

        try:
            self._store.upsert_canonical_findings(merged)
            self._store.save_result(payload)
        except OSError:
            payload.setdefault("metadata", {})["persistence_error"] = True

        return {
            "task_id": task.task_id,
            "correlation_id": task.correlation_id,
            "operation": task.operation,
            "project_id": task.project_id,
            "playbook": task.playbook,
            "status": result.status,
            "result": payload,
            "evaluation": assessment,
            "canonical_findings": canonical_for_task,
            "errors": payload.get("errors", []),
            "metadata": {"agent_id": result.agent_id, "role": result.role},
        }

    def _finalize_many(
        self,
        tasks: list[Task],
        results: list[AgentResult],
        assessments: list[dict[str, Any]],
        *,
        target: str,
        project_id: str,
        playbook: str,
    ) -> dict[str, Any]:
        payloads = [r.to_dict() for r in results]

        canonical = correlation.correlate_results(payloads)
        merged = correlation.merge_canonical(self._store.list_canonical_findings(), canonical)
        merged_by_key = {item["fingerprint"]: item for item in merged}
        canonical_for_task = [
            merged_by_key.get(item["fingerprint"], item) for item in canonical
        ]

        try:
            self._store.upsert_canonical_findings(merged)
            for payload in payloads:
                self._store.save_result(payload)
        except OSError:
            for payload in payloads:
                payload.setdefault("metadata", {})["persistence_error"] = True

        corroborated = [
            item for item in canonical_for_task
            if item.get("validation_state") == "corroborated"
        ]
        single_agent = [
            item for item in canonical_for_task
            if item.get("validation_state") != "corroborated"
        ]

        participating = [
            {
                "agent_id": r.agent_id,
                "role": r.role,
                "task_id": r.task_id,
                "correlation_id": r.correlation_id,
                "status": r.status,
                "finding_count": len(r.findings),
                "evidence_count": len(r.evidence),
                "confidence": r.confidence,
                "engine": r.metadata.get("engine", ""),
            }
            for r in results
        ]

        first = tasks[0] if tasks else None

        return {
            "assessment_id": _assessment_id(project_id, [t.task_id for t in tasks]),
            "project_id": project_id,
            "target": target,
            "playbook": playbook,
            "participating_agents": participating,
            "results": payloads,
            "evaluations": assessments,
            "canonical_findings": canonical_for_task,
            "corroboration": {
                "agent_count": len(participating),
                "distinct_engines": sorted({
                    r.metadata.get("engine", "") for r in results
                    if r.metadata.get("engine")
                }),
                "corroborated_count": len(corroborated),
                "single_agent_count": len(single_agent),
                "independent_corroboration": len(corroborated) > 0,
            },
            "errors": [error for r in results for error in r.errors],
            "metadata": {
                "first_task_id": first.task_id if first else None,
                "first_correlation_id": first.correlation_id if first else None,
            },
        }

    @staticmethod
    def _synthetic(
        task: Task,
        agent_id: str,
        role: str,
        status: AgentStatus,
        reason: AgentStatusReason,
        message: str,
        detail: dict[str, Any] | None = None,
    ) -> AgentResult:
        return AgentResult(
            agent_id=agent_id,
            task_id=task.task_id,
            correlation_id=task.correlation_id,
            role=role,
            status=status.value,
            confidence=0.0,
            errors=(StructuredError(code=reason.value, message=message, detail=dict(detail or {})),),
            metadata={"orchestrator": "security_workforce"},
        )


# ---- adapter builders (lazy imports keep heavy deps out of import time) ----


def _scanner(rule_ids=None, rules=None):
    from .adapters.scanner import ScannerAdapter

    return ScannerAdapter(rule_ids=rule_ids, rules=rules)


def _optional_rule(name: str):
    from scanner.rules import optional

    return getattr(optional, name)()


def _project():
    from .adapters.project import ProjectAdapter

    return ProjectAdapter()


def _hacker_static():
    from .adapters.hacker_static import HackerStaticAdapter

    return HackerStaticAdapter()


def _dynamic():
    from .adapters.dynamic import DynamicValidationAdapter

    return DynamicValidationAdapter()


def _evaluation(store):
    from .adapters.evaluation import EvaluationAdapter

    return EvaluationAdapter(store)


def _verification():
    from .adapters.verification import VerificationAdapter

    return VerificationAdapter()


def _planning(registry):
    from .adapters.orchestration import PlanningAdapter

    return PlanningAdapter(registry)


def _coordination(store):
    from .adapters.orchestration import CoordinationAdapter

    return CoordinationAdapter(store)


def _assessment_id(project_id: str, task_ids: list[str]) -> str:
    import hashlib

    key = "|".join([project_id, *task_ids])
    return "pgassess-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:24]
