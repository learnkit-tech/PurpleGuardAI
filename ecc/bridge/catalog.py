"""Read-only view of the curated ECC snapshot vendored under ``ecc/``.

This is provenance/registration data, not execution: it lets PurpleGuard ask
"what ECC capabilities exist in the snapshot?" without importing ECC internals.
It reads only a fixed set of directories beneath ``ecc/`` and never writes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .contracts import ECC_SOURCE_COMMIT, ECC_SOURCE_REPOSITORY


def ecc_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _read_text(path: Path, limit: int = 200_000) -> str:
    try:
        return path.read_text(errors="ignore")[:limit]
    except OSError:
        return ""


def _frontmatter_description(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("description:"):
            return stripped.split(":", 1)[1].strip().strip("\"'")
    return ""


def _first_heading(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            return stripped.lstrip("#").strip()
    return ""


def _describe_markdown(directory: Path, glob: str) -> list[dict[str, Any]]:
    if not directory.is_dir():
        return []
    entries = []
    for path in sorted(directory.glob(glob)):
        text = _read_text(path)
        entries.append(
            {
                "name": path.stem if path.name != "SKILL.md" else path.parent.name,
                "file": str(path.relative_to(ecc_root())),
                "title": _first_heading(text) or path.stem,
                "description": _frontmatter_description(text),
            }
        )
    return entries


def describe(root: Path | None = None) -> dict[str, Any]:
    """Return a structured catalog of the curated ECC snapshot."""
    base = root or ecc_root()

    agents = _describe_markdown(base / "agents", "*.md")
    commands = _describe_markdown(base / "commands", "*.md")
    skills = _describe_markdown(base / "skills", "*/SKILL.md")
    schemas = [
        {"name": path.name, "file": str(path.relative_to(base))}
        for path in sorted((base / "schemas").glob("*.json"))
    ]
    rules = _describe_markdown(base / "rules" / "common", "*.md")
    rules += _describe_markdown(base / "rules" / "python", "*.md")
    rules += _describe_markdown(base / "rules" / "web", "*.md")

    return {
        "source": {
            "repository": ECC_SOURCE_REPOSITORY,
            "commit": ECC_SOURCE_COMMIT,
            "curated": True,
        },
        "counts": {
            "agents": len(agents),
            "commands": len(commands),
            "skills": len(skills),
            "schemas": len(schemas),
            "rules": len(rules),
        },
        "agents": agents,
        "commands": commands,
        "skills": skills,
        "schemas": schemas,
        "rules": rules,
    }


def emit(root: Path | None = None) -> str:
    return json.dumps(describe(root), indent=2)
