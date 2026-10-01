"""Persistence for workforce results and canonical findings.

A single JSON document at ``reports/security_workforce.json`` (the repo's
``reports/*.json`` entries are gitignored, so runtime state stays out of the
tree). PurpleGuard owns this file.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_PATH = _PROJECT_ROOT / "reports" / "security_workforce.json"


class WorkforceStore:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path is not None else _DEFAULT_PATH

    def _load(self) -> dict[str, Any]:
        if not self.path.is_file():
            return {"results": {}, "canonical_findings": {}}
        try:
            data = json.loads(self.path.read_text())
        except (ValueError, OSError):
            return {"results": {}, "canonical_findings": {}}
        if not isinstance(data, dict):
            return {"results": {}, "canonical_findings": {}}
        data.setdefault("results", {})
        data.setdefault("canonical_findings", {})
        return data

    def _write(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = tempfile.NamedTemporaryFile(
            "w", dir=str(self.path.parent), delete=False, suffix=".tmp"
        )
        try:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        finally:
            handle.close()
        os.replace(handle.name, self.path)

    # ---- results ---------------------------------------------------------

    def save_result(self, result: dict[str, Any]) -> None:
        task_id = result.get("task_id")
        if not task_id:
            raise ValueError("result is missing task_id")
        data = self._load()
        data["results"][task_id] = result
        self._write(data)

    def get_result(self, task_id: str) -> dict[str, Any] | None:
        return self._load()["results"].get(task_id)

    def list_results(self) -> list[dict[str, Any]]:
        return list(self._load()["results"].values())

    # ---- canonical findings ---------------------------------------------

    def upsert_canonical_findings(self, findings: list[dict[str, Any]]) -> None:
        data = self._load()
        for finding in findings:
            key = finding.get("fingerprint")
            if key:
                data["canonical_findings"][key] = finding
        self._write(data)

    def list_canonical_findings(self) -> list[dict[str, Any]]:
        return list(self._load()["canonical_findings"].values())
