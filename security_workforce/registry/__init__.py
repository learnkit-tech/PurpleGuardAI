"""Machine-readable agent registry loader.

Loads ``agents.json`` into :class:`~security_workforce.contracts.AgentSpec`
objects and validates the contract. An agent is only ``available`` when it has a
real adapter; definitions alone are ``defined_only`` and ``enabled: false``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..contracts import AgentSpec

_DEFAULT = Path(__file__).resolve().parent / "agents.json"

_REQUIRED_FIELDS = (
    "agent_id", "name", "role", "mission", "permissions",
    "approval_required", "compatible_tasks", "provenance",
)

_KNOWN_PERMISSIONS = {"observe", "analyze", "validate", "propose", "modify", "verify"}


def _to_spec(raw: dict[str, Any]) -> AgentSpec:
    return AgentSpec(
        agent_id=raw["agent_id"],
        name=raw["name"],
        role=raw["role"],
        mission=raw["mission"],
        capabilities=tuple(raw.get("capabilities", ())),
        knowledge_domains=tuple(raw.get("knowledge_domains", ())),
        skills=tuple(raw.get("skills", ())),
        rules=tuple(raw.get("rules", ())),
        tools=tuple(raw.get("tools", ())),
        inputs=tuple(raw.get("inputs", ())),
        outputs=tuple(raw.get("outputs", ())),
        required_evidence=tuple(raw.get("required_evidence", ())),
        permissions=frozenset(raw.get("permissions", ())),
        approval_required=bool(raw.get("approval_required", True)),
        escalation_conditions=tuple(raw.get("escalation_conditions", ())),
        dependencies=tuple(raw.get("dependencies", ())),
        compatible_tasks=tuple(raw.get("compatible_tasks", ())),
        verification_requirements=tuple(raw.get("verification_requirements", ())),
        risk_level=raw.get("risk_level", "medium"),
        enabled=bool(raw.get("enabled", False)),
        implementation=raw.get("implementation", "defined_only"),
        provenance=dict(raw.get("provenance", {})),
    )


def load_registry(path: str | Path | None = None) -> dict[str, AgentSpec]:
    data = json.loads(Path(path or _DEFAULT).read_text())
    return {raw["agent_id"]: _to_spec(raw) for raw in data["agents"]}


def get_agent(agent_id: str, path: str | Path | None = None) -> AgentSpec | None:
    return load_registry(path).get(agent_id)


def validate_registry(path: str | Path | None = None) -> list[str]:
    """Return a list of problems; empty means valid."""
    problems: list[str] = []
    try:
        data = json.loads(Path(path or _DEFAULT).read_text())
    except (ValueError, OSError) as exc:
        return [f"registry unreadable: {exc}"]

    seen: set[str] = set()
    for raw in data.get("agents", []):
        agent_id = raw.get("agent_id", "<missing>")
        for field_name in _REQUIRED_FIELDS:
            if field_name not in raw:
                problems.append(f"{agent_id}: missing {field_name}")
        if agent_id in seen:
            problems.append(f"{agent_id}: duplicate agent_id")
        seen.add(agent_id)
        unknown = set(raw.get("permissions", ())) - _KNOWN_PERMISSIONS
        if unknown:
            problems.append(f"{agent_id}: unknown permissions {sorted(unknown)}")
        if "modify" in raw.get("permissions", ()):
            problems.append(f"{agent_id}: agents may not hold 'modify'")
        if raw.get("implementation") == "available" and not raw.get("enabled"):
            problems.append(f"{agent_id}: available but not enabled")
        if not raw.get("provenance", {}).get("ecc_source"):
            problems.append(f"{agent_id}: missing ECC provenance")
    return problems


__all__ = ["load_registry", "get_agent", "validate_registry"]
