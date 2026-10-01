"""PurpleGuard Security Agent Workforce.

A PurpleGuard-native subsystem, strengthened by reusable knowledge, agent roles,
skills, rules, workflows, orchestration patterns, and evaluation concepts
extracted from ECC (see ``docs/ECC_CAPABILITY_MAP.md``). ECC is the source;
PurpleGuard is the product; the workforce is the capability.

    from security_workforce import WorkforceOrchestrator

    workforce = WorkforceOrchestrator()
    outcome = workforce.run("security.review", target="/path/to/project")

    # genuine multi-agent discovery + independent validation
    assessment = workforce.assess("/path/to/project")
"""

from __future__ import annotations

from .capabilities import CAPABILITIES, Capability, executable_capabilities, unavailable_capabilities
from .contracts import (
    ECC_SOURCE_COMMIT,
    ECC_SOURCE_REPOSITORY,
    AgentResult,
    AgentSpec,
    AgentStatus,
    AgentStatusReason,
    CapabilityState,
    Evidence,
    Permission,
    RiskLevel,
    StructuredError,
    Task,
    TaskStatus,
    ValidationState,
    deterministic_correlation_id,
    deterministic_task_id,
    make_task,
)
from .context import ContextBuilder, ContextBundle
from .correlation import correlate_results, fingerprint, merge_canonical
from .developer_handoff import DeveloperHandoff
from .evaluation import evaluate_result
from .orchestrator import WorkforceOrchestrator
from .playbooks import get_playbook, load_playbooks
from .registry import get_agent, load_registry, validate_registry
from .store import WorkforceStore

__all__ = [
    "WorkforceOrchestrator",
    "WorkforceStore",
    "DeveloperHandoff",
    "AgentResult",
    "AgentSpec",
    "AgentStatus",
    "AgentStatusReason",
    "Capability",
    "CAPABILITIES",
    "CapabilityState",
    "Evidence",
    "Permission",
    "RiskLevel",
    "StructuredError",
    "Task",
    "TaskStatus",
    "ValidationState",
    "ContextBuilder",
    "ContextBundle",
    "correlate_results",
    "merge_canonical",
    "fingerprint",
    "evaluate_result",
    "load_registry",
    "get_agent",
    "validate_registry",
    "load_playbooks",
    "get_playbook",
    "make_task",
    "deterministic_task_id",
    "deterministic_correlation_id",
    "executable_capabilities",
    "unavailable_capabilities",
    "ECC_SOURCE_REPOSITORY",
    "ECC_SOURCE_COMMIT",
]
