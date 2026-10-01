"""Adapters from workforce agents to PurpleGuard tools and engines.

Every adapter here is a real, read-only seam. None of them modify the
target; remediation lives behind the human approval gate.
"""

from __future__ import annotations

from .base import Adapter, AdapterError, AdapterOutput, EngineUnavailable, InvalidTarget
from .dynamic import DynamicValidationAdapter
from .evaluation import EvaluationAdapter
from .hacker_static import CATEGORY_TO_RULE, HackerStaticAdapter
from .orchestration import CoordinationAdapter, PlanningAdapter
from .project import ProjectAdapter
from .scanner import ScannerAdapter
from .verification import VerificationAdapter

__all__ = [
    "Adapter",
    "AdapterError",
    "AdapterOutput",
    "EngineUnavailable",
    "InvalidTarget",
    "ScannerAdapter",
    "ProjectAdapter",
    "HackerStaticAdapter",
    "DynamicValidationAdapter",
    "EvaluationAdapter",
    "VerificationAdapter",
    "PlanningAdapter",
    "CoordinationAdapter",
    "CATEGORY_TO_RULE",
]
