#!/usr/bin/env python3
"""Phase 4.1 tests — evidence & context integrity. No network required."""
import os
import sys
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(os.path.dirname(_HERE))
sys.path.insert(0, _HERE)
sys.path.insert(0, _REPO_ROOT)

from hacker.findings import FindingBuilder            # noqa: E402
from hacker.reverification import HackerReverification  # noqa: E402
from engine_adapter import _map_hacker_finding        # noqa: E402

ATTACK_PATHS = [{
    "id": "PATH-1", "title": "t", "category": "SQL_INJECTION",
    "severity": "HIGH", "confidence": 0.95, "status": "POTENTIAL_ATTACK_PATH",
    "impact": "i", "nodes": [
        {"id": "SOURCE-1", "kind": "SOURCE", "name": "username",
         "location": {"file": "app.py", "line": 10, "code": "u = request.args.get('username')"},
         "description": "entry"},
        {"id": "SINK-1", "kind": "SINK", "name": "execute",
         "location": {"file": "app.py", "line": 20, "code": "c.execute(q)"},
         "description": "sink"},
    ],
}]
PLANS = [{"path_id": "PATH-1", "category": "SQL_INJECTION", "severity": "HIGH",
          "confidence": 0.95, "validator": "validate_sql_behavior"}]
REQUEST = {"status": 200, "body": "<html>rows</html>",
           "headers": {"Content-Type": "text/html"},
           "url": "http://127.0.0.1:9/search?username=x"}
VALIDATION = {"path_id": "PATH-1", "category": "SQL_INJECTION", "severity": "HIGH",
              "validator": "validate_sql_behavior", "payload": "' OR '1'='1",
              "validated": True, "evidence": "behavior changed", "request": REQUEST}


class TestFindingArtifacts(unittest.TestCase):
    def test_builder_preserves_request_artifact(self):
        f = FindingBuilder().build(ATTACK_PATHS, PLANS, [VALIDATION])
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].request.get("status"), 200)
        self.assertEqual(f[0].request.get("body"), "<html>rows</html>")

    def test_builder_records_honest_validation(self):
        f = FindingBuilder().build(
            ATTACK_PATHS, PLANS, [dict(VALIDATION, validated=False)])
        self.assertFalse(f[0].validated)


class TestAdapterEvidence(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        with open(os.path.join(self.tmp, "app.py"), "w") as fh:
            fh.write("line one\n" * 25)

    def _payload(self, request):
        cf = FindingBuilder().build(
            ATTACK_PATHS, PLANS, [dict(VALIDATION, request=request)])[0].to_dict()
        return _map_hacker_finding(
            self.tmp, cf, {p["id"]: p for p in ATTACK_PATHS})

    def test_evidence_includes_http_artifacts(self):
        payload = self._payload(REQUEST)
        ids = {e["id"] for e in payload["evidence"]}
        self.assertIn("ev-http-status", ids)
        self.assertIn("ev-http-body", ids)
        body = next(e for e in payload["evidence"] if e["id"] == "ev-http-body")
        self.assertIn("rows", body["content"])

    def test_no_http_evidence_when_absent(self):
        payload = self._payload(None)
        self.assertFalse(
            any(e["id"].startswith("ev-http") for e in payload["evidence"]))


class TestRetestVerdicts(unittest.TestCase):
    """Requirement 7: fixed vs still-vulnerable vs unable-to-verify."""

    def test_all_blocked_is_verified(self):
        self.assertEqual(
            HackerReverification.verdict([{"blocked": True}])["status"],
            "SECURITY_VERIFIED")

    def test_any_still_works_is_not_verified(self):
        self.assertEqual(
            HackerReverification.verdict(
                [{"blocked": True}, {"blocked": False}])["status"],
            "SECURITY_NOT_VERIFIED")

    def test_empty_is_unable_to_verify(self):
        self.assertEqual(
            HackerReverification.verdict([])["status"], "NOT_VERIFIED")


if __name__ == "__main__":
    unittest.main()
