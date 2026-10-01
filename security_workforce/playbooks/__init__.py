"""Security playbook registry: workflows agents participate in."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_DEFAULT = Path(__file__).resolve().parent / "registry.json"

_REQUIRED = (
    "playbook_id", "name", "trigger", "required_context", "participating_agents",
    "steps", "evidence_requirements", "approval_gate", "expected_outputs",
    "verification_requirements", "failure_handling",
)


def load_playbooks(path: str | Path | None = None) -> dict[str, dict[str, Any]]:
    data = json.loads(Path(path or _DEFAULT).read_text())
    return {pb["playbook_id"]: pb for pb in data["playbooks"]}


def get_playbook(playbook_id: str, path: str | Path | None = None) -> dict[str, Any] | None:
    return load_playbooks(path).get(playbook_id)


def validate_playbooks(path: str | Path | None = None) -> list[str]:
    problems: list[str] = []
    try:
        playbooks = load_playbooks(path)
    except (ValueError, OSError) as exc:
        return [f"playbooks unreadable: {exc}"]
    for playbook_id, playbook in playbooks.items():
        for field_name in _REQUIRED:
            if field_name not in playbook:
                problems.append(f"{playbook_id}: missing {field_name}")
    return problems


__all__ = ["load_playbooks", "get_playbook", "validate_playbooks"]
