"""End-to-end tests for the workforce API (the real Hacker backend).

These drive the real Flask entrypoint the UI talks to: assess ->
handoff -> explicit approval -> remediation -> genuine re-test. State is
isolated to a temp directory by swapping the API's state helpers, so no
repo artifact or developer status file is touched.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import api.server as srv  # noqa: E402
from security_workforce import DeveloperHandoff, WorkforceOrchestrator, WorkforceStore  # noqa: E402

VULN_EVAL = "def run(x):\n    return eval(x)\n"


class WorkforceApiTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        state = Path(self._tmp.name)

        self._orig_orch = srv._workforce_orchestrator
        self._orig_handoff = srv._workforce_handoff
        srv._workforce_orchestrator = lambda: WorkforceOrchestrator(
            store=WorkforceStore(state / "wf.json")
        )
        srv._workforce_handoff = lambda wf: DeveloperHandoff(
            wf.store,
            handoff_path=state / "handoff.json",
            status_path=state / "dev_status.json",
        )
        self.addCleanup(self._restore)

        self.state = state
        self.client = srv.app.test_client()

        self.target = state / "authorized"
        self.target.mkdir()
        self.file = self.target / "a.py"
        self.file.write_text(VULN_EVAL)

    def _restore(self):
        srv._workforce_orchestrator = self._orig_orch
        srv._workforce_handoff = self._orig_handoff

    def _assess(self):
        resp = self.client.post("/workforce/assess", json={"target": str(self.target)})
        self.assertEqual(resp.status_code, 200)
        return resp.get_json()["assessment"]

    # ---- read endpoints --------------------------------------------------

    def test_capabilities_endpoint_reports_honest_states(self):
        payload = self.client.get("/workforce/capabilities").get_json()
        caps = {c["agent_id"]: c for c in payload["capabilities"]}
        self.assertEqual(len(caps), 20)
        self.assertEqual(caps["security-reviewer"]["state"], "AVAILABLE")
        self.assertEqual(caps["loop-operator"]["state"], "UNAVAILABLE")
        self.assertTrue(caps["loop-operator"]["unavailable_reason"])

    def test_read_only_findings_endpoint_does_not_write_state(self):
        store_file = self.state / "wf.json"
        self.assertFalse(store_file.exists())
        resp = self.client.get("/workforce/findings")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["count"], 0)
        # A read endpoint must not create or touch persisted state.
        self.assertFalse(store_file.exists())

    # ---- assess ----------------------------------------------------------

    def test_assess_returns_corroborated_canonical_and_persists(self):
        assessment = self._assess()
        self.assertTrue(assessment["corroboration"]["independent_corroboration"])
        canonical = assessment["canonical_findings"][0]
        self.assertEqual(canonical["rule_id"], "PG002")
        self.assertEqual(canonical["validation_state"], "corroborated")
        self.assertTrue(canonical["evidence"])

        # the same canonical finding is now readable through the read endpoint
        findings = self.client.get("/workforce/findings").get_json()
        self.assertEqual(findings["count"], 1)
        self.assertEqual(findings["findings"][0]["fingerprint"], canonical["fingerprint"])

    def test_assess_validates_target_deterministically(self):
        self.assertEqual(
            self.client.post("/workforce/assess", json={}).status_code, 400
        )
        self.assertEqual(
            self.client.post("/workforce/assess", json={"target": "/no/such/dir"}).status_code,
            400,
        )

    # ---- handoff ---------------------------------------------------------

    def test_handoff_requires_target_and_does_not_modify_source(self):
        before = self.file.read_bytes()
        self.assertEqual(self.client.post("/workforce/handoff", json={}).status_code, 400)

        self._assess()
        resp = self.client.post("/workforce/handoff", json={"target": str(self.target)})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["status"], "AWAITING_APPROVAL")
        self.assertEqual(self.file.read_bytes(), before)

        pending = self.client.get("/workforce/handoff").get_json()["pending"]
        self.assertEqual(len(pending), 1)

    # ---- approval -> remediation -> re-test ------------------------------

    def test_approval_gate_and_verified_re_test(self):
        assessment = self._assess()
        fingerprint = assessment["canonical_findings"][0]["fingerprint"]
        self.client.post("/workforce/handoff", json={"target": str(self.target)})

        before = self.file.read_bytes()

        # No explicit approval -> nothing modified.
        resp = self.client.post("/workforce/approve", json={"fingerprint": fingerprint})
        self.assertEqual(resp.get_json()["status"], "APPROVAL_REQUIRED")
        self.assertEqual(self.file.read_bytes(), before)

        # Unknown fingerprint -> deterministic 404, no execution.
        self.assertEqual(
            self.client.post(
                "/workforce/approve", json={"fingerprint": "pgfingerprint-nope"}
            ).status_code,
            404,
        )
        self.assertEqual(
            self.client.post("/workforce/approve", json={}).status_code, 400
        )

        # Explicit approval -> remediation -> genuine re-test -> VERIFIED.
        resp = self.client.post(
            "/workforce/approve",
            json={"fingerprint": fingerprint, "approve": True},
        )
        self.assertEqual(resp.status_code, 200)
        result = resp.get_json()
        self.assertEqual(result["status"], "VERIFIED")
        self.assertTrue(result["verification"]["verified"])
        self.assertIn("ast.literal_eval", self.file.read_text())

    def test_no_secrets_in_workforce_endpoint_payloads(self):
        """Endpoint payloads must not leak environment secrets."""
        import os

        assessment = self._assess()
        blob = json.dumps(assessment)
        for key, value in os.environ.items():
            if value and len(value) >= 12 and ("KEY" in key or "TOKEN" in key or "SECRET" in key):
                self.assertNotIn(value, blob)


if __name__ == "__main__":
    unittest.main()
