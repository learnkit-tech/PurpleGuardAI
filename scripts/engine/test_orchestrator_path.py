#!/usr/bin/env python3
"""End-to-end path tests for the engine loop, with the HTTP boundary mocked.

The mock server replays the real deployment's response shapes (verified live
in earlier turns), so claim -> fetch -> validate -> ingest -> resolve runs
with REAL validators and only the network faked.

Run: cd scripts/engine && python3 -m unittest test_orchestrator_path -v
"""

from __future__ import annotations

import json
import unittest
from typing import Any, Dict, List, Optional
from unittest.mock import patch

import orchestrator as orch
from validators import validate

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
RUN_ID = "j57run0001"


class FakeDeployment:
    """Minimal stand-in for the Convex HTTP routes, shaped per docs/ENGINE_API.md."""

    def __init__(self) -> None:
        self.runs: List[Dict[str, Any]] = []
        self.resolutions: List[Dict[str, Any]] = []
        self.ingested: List[Dict[str, Any]] = []

    def add_queued_run(self, project: str, kind: str = "validation") -> None:
        scope = {"authorizedPaths": ["/**"], "blockedPaths": []}
        self.runs.append({
            "_id": RUN_ID,
            "projectId": project,
            "kind": kind,
            "scope": scope,
        })

    def api(self, path: str, method: str = "GET", body: Optional[Dict[str, Any]] = None) -> Any:
        if path == "/api/runs/pending" and method == "GET":
            return {"runs": list(self.runs)}
        if path == "/api/runs/claim" and method == "POST":
            run_id = (body or {}).get("runId")
            for i, r in enumerate(self.runs):
                if r["_id"] == run_id:
                    claimed = self.runs.pop(i)
                    return {
                        "ok": True,
                        "projectId": claimed["projectId"],
                        "kind": claimed["kind"],
                        "scope": claimed["scope"],
                    }
            return {"ok": False, "reason": "run is no longer queued"}
        if path == "/api/ingest_finding" and method == "POST":
            payload = body or {}
            if "id" not in payload or not payload.get("attackSteps"):
                raise RuntimeError("422: payload.id/attackSteps required")
            self.ingested.append(payload)
            return {"findingId": payload["id"], "updated": False}
        if path == "/api/runs/resolve" and method == "POST":
            self.resolutions.append(body or {})
            return {"ok": True}
        raise RuntimeError(f"unrouted: {method} {path}")


class Base(unittest.TestCase):
    def setUp(self) -> None:
        self.dep = FakeDeployment()
        self.p_api = patch.object(orch, "api", side_effect=self.dep.api)
        self.p_api.start()
        self.addCleanup(self.p_api.stop)


class FullPathTests(Base):
    FILES = [
        {"path": "src/config/auth.ts", "content": f'export const K = "{AWS_KEY}";\n'},
        {"path": "src/clean.ts", "content": "export const add = (a, b) => a + b;\n"},
        {"path": "vendor/out.js", "content": AWS_KEY},  # must never be inspected
    ]

    def test_full_path_with_real_validators(self) -> None:
        self.dep.add_queued_run("acme/widget-co")
        with patch.object(orch, "fetch_repo_files", return_value=list(self.FILES)):
            orch.handle_run(self.dep.runs[0], dry_run=False)

        # 1. Exactly one run resolved, honestly, with the true count.
        self.assertEqual(len(self.dep.resolutions), 1)
        res = self.dep.resolutions[0]
        self.assertEqual(res["runId"], RUN_ID)
        self.assertTrue(res["ok"])
        self.assertEqual(res["findingsIngested"], 1)

        # 2. The finding is real, structured, and scope-clean.
        self.assertEqual(len(self.dep.ingested), 1)
        f = self.dep.ingested[0]
        self.assertEqual(f["repo"], "acme/widget-co")
        self.assertEqual(f["file"], "src/config/auth.ts")
        self.assertNotEqual(f["file"], "vendor/out.js")  # blocked path respected
        # Redacted surfaces (evidence/marker) never carry the raw secret;
        # vulnerableCode is intentionally raw — it seeds the Developer
        # workspace buffer that an approval applies back to the repo.
        self.assertNotIn(AWS_KEY, json.dumps([f["evidence"], f["vulnerableMarker"]]))
        self.assertIn(AWS_KEY, f["vulnerableCode"])
        self.assertTrue(f["attackSteps"])

    def test_dry_run_never_fetches_never_validates(self) -> None:
        self.dep.add_queued_run("acme/widget-co")
        with patch.object(orch, "fetch_repo_files") as mock_fetch:
            orch.handle_run(self.dep.runs[0], dry_run=True)
        mock_fetch.assert_not_called()          # dry run does not touch target
        self.assertEqual(self.dep.ingested, [])  # and never invents findings
        res = self.dep.resolutions[0]
        self.assertFalse(res["ok"])              # honest failure, not a fake pass
        self.assertEqual(res["findingsIngested"], 0)
        self.assertIn("no validation executed", res["note"])

    def test_unfetchable_target_resolves_honestly(self) -> None:
        self.dep.add_queued_run("acme/private-repo")
        with patch.object(orch, "fetch_repo_files", return_value=[]):
            orch.handle_run(self.dep.runs[0], dry_run=False)
        res = self.dep.resolutions[0]
        self.assertFalse(res["ok"])
        self.assertEqual(res["findingsIngested"], 0)
        self.assertIn("not fetchable", res["note"])

    def test_fetch_failure_resolves_honestly(self) -> None:
        self.dep.add_queued_run("acme/broken")
        with patch.object(orch, "fetch_repo_files", side_effect=RuntimeError("gh api down")):
            orch.handle_run(self.dep.runs[0], dry_run=False)
        res = self.dep.resolutions[0]
        self.assertFalse(res["ok"])
        self.assertIn("target fetch failed", res["note"])

    def test_zero_findings_is_an_ok_run(self) -> None:
        self.dep.add_queued_run("acme/clean")
        with patch.object(orch, "fetch_repo_files", return_value=[
            {"path": "src/app.ts", "content": "export const ok = 1;\n"}
        ]):
            orch.handle_run(self.dep.runs[0], dry_run=False)
        res = self.dep.resolutions[0]
        self.assertTrue(res["ok"])               # run executed to completion
        self.assertEqual(res["findingsIngested"], 0)  # honestly zero
        self.assertIn("0 finding(s) pushed", res["note"])

    def test_bad_finding_does_not_kill_run(self) -> None:
        self.dep.add_queued_run("acme/mixed")
        files = [{"path": "src/a.ts", "content": AWS_KEY}]
        with patch.object(orch, "fetch_repo_files", return_value=files), \
             patch.object(orch, "ingest_finding", side_effect=[
                 RuntimeError("422: ingest exploded"),
                 {"findingId": "PG-x", "updated": False},
             ]) as mock_ingest, \
             patch("orchestrator.validate") as mock_validate:
            mock_validate.side_effect = lambda p, fs, s: validate(p, fs, s) + [
                {"id": "BROKEN-1", "attackSteps": []}  # simulate a malformed extra
            ]
            orch.handle_run(self.dep.runs[0], dry_run=False)
        self.assertEqual(mock_ingest.call_count, 2)     # both attempted
        self.assertEqual(len(self.dep.resolutions), 1)
        self.assertTrue(self.dep.resolutions[0]["ok"])
        self.assertEqual(self.dep.resolutions[0]["findingsIngested"], 1)
        self.assertIn("1 ingest error(s)", self.dep.resolutions[0]["note"])

    def test_scope_narrowing_flows_through(self) -> None:
        self.dep.add_queued_run("acme/scoped")
        self.dep.runs[0]["scope"] = {"authorizedPaths": ["src/**"], "blockedPaths": []}
        files = [
            {"path": "src/a.ts", "content": AWS_KEY},
            {"path": "etc/secret.pem", "content": "-----BEGIN RSA PRIVATE KEY-----"},
        ]
        with patch.object(orch, "fetch_repo_files", return_value=files):
            orch.handle_run(self.dep.runs[0], dry_run=False)
        self.assertEqual(len(self.dep.ingested), 1)
        self.assertEqual(self.dep.ingested[0]["file"], "src/a.ts")


if __name__ == "__main__":
    unittest.main(verbosity=2)
