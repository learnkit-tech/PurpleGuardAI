"""Hacker -> Developer handoff.

Connects real canonical workforce findings to PurpleGuard's existing
developer workflow:

    canonical finding
      -> developer inbox (awaiting_approval)
      -> explicit approval
      -> remediation (existing RemediationWorkflow)
      -> re-test (existing SecurityScanner)
      -> verification

Rules enforced here:

* Approval is a real gate. ``approve_and_remediate`` without
  ``approve=True`` never touches source.
* A remediation is **never** auto-verified. ``verified`` is set only
  when a genuine re-test - a fresh scan of the target - shows the
  original rule no longer fires at the finding's location.
* This reuses PurpleGuard's existing remediation + scanner engines; it
  is not a parallel backend.
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_HANDOFF = _PROJECT_ROOT / "reports" / "security_workforce_handoff.json"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class DeveloperHandoff:
    def __init__(
        self,
        store,
        *,
        handoff_path: str | Path | None = None,
        status_path: str | Path | None = None,
    ) -> None:
        self._store = store
        self._handoff_path = Path(handoff_path) if handoff_path is not None else _DEFAULT_HANDOFF
        self._status_path = status_path

    # ---- persistence -----------------------------------------------------

    def _load(self) -> dict[str, Any]:
        if not self._handoff_path.is_file():
            return {"items": {}}
        try:
            data = json.loads(self._handoff_path.read_text())
        except (ValueError, OSError):
            return {"items": {}}
        if not isinstance(data, dict):
            return {"items": {}}
        data.setdefault("items", {})
        return data

    def _write(self, data: dict[str, Any]) -> None:
        self._handoff_path.parent.mkdir(parents=True, exist_ok=True)
        handle = tempfile.NamedTemporaryFile(
            "w", dir=str(self._handoff_path.parent), delete=False, suffix=".tmp"
        )
        try:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        finally:
            handle.close()
        os.replace(handle.name, self._handoff_path)

    def _record_status(self, stage: str, findings: list[dict[str, Any]]) -> None:
        """Mirror the handoff into the developer workspace status file."""
        try:
            from dev_agent.status import update_status

            path = self._status_path or str(_PROJECT_ROOT / "dev_agent" / "status.json")
            current: dict[str, Any] = {}
            if os.path.exists(path):
                try:
                    current = json.loads(Path(path).read_text())
                except (ValueError, OSError):
                    current = {}
            current["security"] = {
                "stage": stage,
                "finding_count": len(findings),
                "findings": findings,
                "recorded_from": "security_workforce",
            }
            update_status(current, path=str(path))
        except Exception:
            pass

    # ---- handoff ---------------------------------------------------------

    def send(
        self,
        canonical_findings: list[dict[str, Any]],
        *,
        project_id: str = "purpleguard",
        target: str,
    ) -> dict[str, Any]:
        data = self._load()
        items = data["items"]
        delivered = []

        for finding in canonical_findings:
            fingerprint = finding.get("fingerprint")
            if not fingerprint:
                continue
            existing = items.get(fingerprint, {})
            # Never regress a verified item back to awaiting_approval.
            stage = (
                "verified"
                if existing.get("stage") == "verified"
                else "awaiting_approval"
            )
            items[fingerprint] = {
                "fingerprint": fingerprint,
                "project_id": project_id,
                "target": target,
                "rule_id": finding.get("rule_id"),
                "name": finding.get("name"),
                "severity": finding.get("severity"),
                "file": finding.get("file"),
                "line": finding.get("line"),
                "code": finding.get("code"),
                "validation_state": finding.get("validation_state"),
                "sources": finding.get("sources", []),
                "evidence": finding.get("evidence", []),
                "stage": stage,
                "verification": existing.get("verification"),
                "created_at": existing.get("created_at", _now()),
                "updated_at": _now(),
            }
            delivered.append(items[fingerprint])

        self._write(data)
        self._record_status("awaiting_approval", delivered)
        return {
            "status": "AWAITING_APPROVAL",
            "delivered": len(delivered),
            "items": delivered,
        }

    def pending(self) -> list[dict[str, Any]]:
        return [
            item for item in self._load()["items"].values()
            if item.get("stage") == "awaiting_approval"
        ]

    def get(self, fingerprint: str) -> dict[str, Any] | None:
        return self._load()["items"].get(fingerprint)

    # ---- approval -> remediation -> re-test -> verification --------------

    def re_test(self, fingerprint: str, *, target: str | None = None) -> dict[str, Any]:
        """Genuine re-test: a fresh scanner run must no longer flag the rule."""
        item = self.get(fingerprint)
        if item is None:
            return {"verified": False, "status": "NOT_FOUND", "fingerprint": fingerprint}

        scan_target = target or item.get("target")
        if not scan_target or not os.path.isdir(scan_target):
            return {
                "verified": False,
                "status": "INVALID_TARGET",
                "fingerprint": fingerprint,
                "target": scan_target,
            }

        from scanner.engine import SecurityScanner
        from scanner.rules.optional import OPTIONAL_RULES
        from scanner.rules.registry import RULES

        # Re-test with the default rule set plus the optional engine
        # rules (e.g. PG011/PG012), so a finding produced by an optional
        # rule is verified against the rule that actually produced it.
        findings = SecurityScanner(
            scan_target, rules=list(RULES) + list(OPTIONAL_RULES)
        ).scan()
        remaining = [
            f for f in findings
            if f.get("id") == item.get("rule_id")
            and os.path.basename(str(f.get("file", ""))) == os.path.basename(str(item.get("file", "")))
        ]

        verified = len(remaining) == 0
        result = {
            "verified": verified,
            "status": "VERIFIED" if verified else "STILL_PRESENT",
            "fingerprint": fingerprint,
            "rule_id": item.get("rule_id"),
            "remaining": remaining,
            "evidence": {
                "what_tested": f"re-test of {item.get('rule_id')} at {item.get('file')}:{item.get('line')}",
                "where_tested": f"{os.path.basename(str(item.get('file', '')))}:{item.get('line')}",
                "what_happened": (
                    "rule no longer fires after remediation"
                    if verified
                    else f"rule still fires ({len(remaining)} occurrence(s))"
                ),
                "timestamp": _now(),
            },
        }

        data = self._load()
        if fingerprint in data["items"]:
            data["items"][fingerprint]["verification"] = result
            data["items"][fingerprint]["stage"] = "verified" if verified else "not_verified"
            data["items"][fingerprint]["updated_at"] = _now()
            self._write(data)

        return result

    def approve_and_remediate(
        self,
        fingerprint: str,
        *,
        approve: bool = False,
        target: str | None = None,
    ) -> dict[str, Any]:
        item = self.get(fingerprint)
        if item is None:
            return {"status": "NOT_FOUND", "fingerprint": fingerprint}

        if not approve:
            return {
                "status": "APPROVAL_REQUIRED",
                "fingerprint": fingerprint,
                "message": "No source was modified. Set approve=True to apply remediation.",
                "item": item,
            }

        scan_target = target or item.get("target")
        if not scan_target or not os.path.isdir(scan_target):
            return {"status": "INVALID_TARGET", "fingerprint": fingerprint, "target": scan_target}

        finding = {
            "id": item.get("rule_id"),
            "file": item.get("file"),
            "line": item.get("line"),
            "code": item.get("code"),
        }

        from scanner.remediation.workflow import RemediationWorkflow

        workflow = RemediationWorkflow(scan_target)
        remediation = workflow.apply_patches([finding], approved=True)

        applied = remediation.get("status") == "APPLIED" and any(
            result.get("status") == "APPLIED" for result in remediation.get("results", [])
        )

        # Verification must come from a real re-test, never from the
        # fact that a patch was written.
        verification = self.re_test(fingerprint, target=scan_target)

        if not applied:
            stage = "remediation_unavailable"
        elif verification.get("verified"):
            stage = "verified"
        else:
            stage = "remediated_not_verified"

        data = self._load()
        if fingerprint in data["items"]:
            data["items"][fingerprint]["stage"] = stage
            data["items"][fingerprint]["remediation"] = {
                "status": remediation.get("status"),
                "results": remediation.get("results", []),
            }
            data["items"][fingerprint]["verification"] = verification
            data["items"][fingerprint]["updated_at"] = _now()
            self._write(data)

        status = {
            "verified": "VERIFIED",
            "remediated_not_verified": "REMEDIATED_NOT_VERIFIED",
            "remediation_unavailable": "REMEDIATION_UNAVAILABLE",
        }[stage]

        self._record_status(stage, [data["items"].get(fingerprint, item)])

        return {
            "status": status,
            "fingerprint": fingerprint,
            "remediation": remediation,
            "verification": verification,
            "stage": stage,
        }


__all__ = ["DeveloperHandoff"]
