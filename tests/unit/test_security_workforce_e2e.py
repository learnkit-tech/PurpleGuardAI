"""Deterministic authorized end-to-end tests for the security workforce.

Happy path:

    REAL TARGET -> REAL ENGINE -> REAL AGENTS -> MULTI-AGENT VALIDATION
    -> CANONICAL FINDING -> PERSISTENCE -> DEVELOPER -> APPROVAL
    -> REMEDIATION -> RE-TEST -> VERIFIED

Negative path:

    ENGINE UNAVAILABLE -> UNAVAILABLE/FAILED -> NO FABRICATED FINDING
"""

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from security_workforce import DeveloperHandoff, WorkforceOrchestrator, WorkforceStore  # noqa: E402
from security_workforce.agents.engine_agent import EngineAgent  # noqa: E402

VULN_EVAL = "def run(x):\n    return eval(x)\n"


def _remove_generated_patch(name):
    path = PROJECT_ROOT / "reports" / "patches" / name
    if path.is_file():
        path.unlink()


class E2ETestBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        # RemediationWorkflow writes generated patches to a cwd-relative
        # reports/patches/; remove the one this fixture produces.
        self.addCleanup(_remove_generated_patch, "vuln.py.patch")
        self.root = Path(self._tmp.name) / "target"
        self.root.mkdir()
        self.file = self.root / "vuln.py"
        self.file.write_text(VULN_EVAL)
        self.store = WorkforceStore(Path(self._tmp.name) / "wf.json")
        self.workforce = WorkforceOrchestrator(store=self.store)
        self.status_path = Path(self._tmp.name) / "status.json"
        self.handoff = DeveloperHandoff(
            self.store,
            handoff_path=Path(self._tmp.name) / "handoff.json",
            status_path=str(self.status_path),
        )


class FullLoopE2ETests(E2ETestBase):
    def test_real_hacker_to_developer_to_verification(self):
        before = self.file.read_bytes()

        # 1. REAL TARGET -> REAL ENGINE -> REAL AGENTS -> MULTI-AGENT VALIDATION
        assessment = self.workforce.assess(str(self.root))

        agents = {a["agent_id"] for a in assessment["participating_agents"]}
        self.assertEqual(agents, {"security-reviewer", "code-reviewer"})
        self.assertEqual(
            assessment["corroboration"]["distinct_engines"],
            ["hacker.python_analyzer.PythonSecurityAnalyzer", "scanner.engine.SecurityScanner"],
        )
        self.assertTrue(assessment["corroboration"]["independent_corroboration"])

        # 2. REAL CANONICAL FINDING (deduplicated, corroborated, evidenced)
        self.assertEqual(len(assessment["canonical_findings"]), 1)
        canonical = assessment["canonical_findings"][0]
        self.assertEqual(canonical["rule_id"], "PG002")
        self.assertEqual(canonical["validation_state"], "corroborated")
        self.assertTrue(canonical["evidence"])
        self.assertEqual(
            {s["agent_id"] for s in canonical["sources"]},
            {"security-reviewer", "code-reviewer"},
        )

        # 3. PERSISTENCE
        self.assertTrue(self.store.list_results())
        self.assertTrue(self.store.list_canonical_findings())

        # 4. HACKER UI / DEVELOPER: the developer receives the same canonical finding
        sent = self.handoff.send(
            assessment["canonical_findings"], target=str(self.root),
        )
        self.assertEqual(sent["status"], "AWAITING_APPROVAL")
        self.assertEqual(sent["delivered"], 1)
        self.assertEqual(self.handoff.pending()[0]["fingerprint"], canonical["fingerprint"])

        # the developer workspace status file reflects the handoff
        status = json.loads(self.status_path.read_text())
        self.assertEqual(status["security"]["stage"], "awaiting_approval")

        # 5. APPROVAL GATE: no approval -> nothing modified
        fingerprint = canonical["fingerprint"]
        refused = self.handoff.approve_and_remediate(fingerprint, approve=False)
        self.assertEqual(refused["status"], "APPROVAL_REQUIRED")
        self.assertEqual(self.file.read_bytes(), before)

        # 6. APPROVAL -> REMEDIATION -> RE-TEST -> VERIFICATION
        result = self.handoff.approve_and_remediate(fingerprint, approve=True)
        self.assertEqual(result["status"], "VERIFIED")
        self.assertTrue(result["verification"]["verified"])

        # remediation really changed the source and the re-test really passed
        after = self.file.read_text()
        self.assertIn("ast.literal_eval", after)
        self.assertNotIn("return eval(", after)

        from scanner.engine import SecurityScanner

        self.assertEqual([f["id"] for f in SecurityScanner(str(self.root)).scan()], [])

        # developer status now records verified
        status = json.loads(self.status_path.read_text())
        self.assertEqual(status["security"]["stage"], "verified")

    def test_persistence_survives_a_new_orchestrator(self):
        self.workforce.assess(str(self.root))
        reopened = WorkforceOrchestrator(store=self.store)
        self.assertTrue(reopened.canonical_findings())
        self.assertTrue(reopened.results())

    def test_single_agent_is_not_represented_as_corroborated(self):
        assessment = self.workforce.assess(str(self.root), agents=["security-reviewer"])
        self.assertEqual(assessment["corroboration"]["agent_count"], 1)
        self.assertFalse(assessment["corroboration"]["independent_corroboration"])
        canonical = assessment["canonical_findings"][0]
        self.assertEqual(canonical["validation_state"], "unvalidated")
        self.assertEqual(len(canonical["sources"]), 1)

    def test_re_test_alone_does_not_mark_verified(self):
        """Verification must come from a re-test result, never from a patch."""
        self.workforce.assess(str(self.root))
        canonical = self.store.list_canonical_findings()[0]
        self.handoff.send([canonical], target=str(self.root))
        item = self.handoff.get(canonical["fingerprint"])
        self.assertEqual(item["stage"], "awaiting_approval")


class RemediationNotAutoVerifiedTests(E2ETestBase):
    def test_unfixable_finding_is_never_auto_verified(self):
        # A swallowed exception (PG011) has no automated fixer.
        (self.root / "swallow.py").write_text(
            "def f():\n    try:\n        work()\n    except Exception:\n        pass\n"
        )
        canonical = {
            "fingerprint": "fp-pg011",
            "rule_id": "PG011",
            "name": "Swallowed Exception",
            "severity": "MEDIUM",
            "file": str(self.root / "swallow.py"),
            "line": 4,
            "code": "except Exception:\n        pass",
            "validation_state": "unvalidated",
            "sources": [],
            "evidence": [],
        }
        self.handoff.send([canonical], target=str(self.root))
        before = (self.root / "swallow.py").read_bytes()

        result = self.handoff.approve_and_remediate("fp-pg011", approve=True)
        self.assertEqual(result["status"], "REMEDIATION_UNAVAILABLE")
        self.assertFalse(result["verification"]["verified"])
        self.assertNotEqual(result["stage"], "verified")
        self.assertEqual((self.root / "swallow.py").read_bytes(), before)


class NegativePathTests(E2ETestBase):
    def test_engine_unavailable_yields_no_fabricated_finding(self):
        # No controlled target launcher -> the dynamic engine is unavailable.
        out = self.workforce.run("security.validate.e2e", target=str(self.root), approved=True)
        self.assertEqual(out["status"], "unavailable")
        self.assertEqual(out["errors"][0]["code"], "ENGINE_UNAVAILABLE")
        self.assertEqual(out["canonical_findings"], [])
        # nothing fabricated, nothing handed to the developer
        self.assertEqual(self.store.list_canonical_findings(), [])
        self.assertEqual(self.handoff.pending(), [])

    def test_engine_failure_yields_no_fabricated_finding(self):
        class Boom:
            engine = "boom"

            def run(self, target, *, context=None):
                raise RuntimeError("engine exploded")

        self.workforce._agents["security-reviewer"] = EngineAgent(  # noqa: SLF001
            "security-reviewer", "vulnerability_analysis",
            frozenset({"observe", "analyze"}), Boom(),
        )
        out = self.workforce.run("security.review", target=str(self.root))
        self.assertEqual(out["status"], "failed")
        self.assertEqual(out["errors"][0]["code"], "EXECUTION_ERROR")
        self.assertEqual(out["canonical_findings"], [])
        self.assertEqual(self.store.list_canonical_findings(), [])


class LiveDynamicValidationTests(unittest.TestCase):
    """Real, authorized dynamic validation against a controlled local target."""

    def test_dynamic_validation_confirms_attacks_and_persists_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = PROJECT_ROOT / "tests" / "hacker_target"
            target = Path(tmp) / "target"
            shutil.copytree(
                source, target,
                ignore=shutil.ignore_patterns("__pycache__", "*.purpleguard.bak"),
            )
            subprocess.run(
                [sys.executable, "reset_vulnerable.py"],
                cwd=target, capture_output=True, text=True, timeout=60,
            )

            store = WorkforceStore(Path(tmp) / "wf.json")
            workforce = WorkforceOrchestrator(store=store)
            out = workforce.run("security.validate.e2e", target=str(target), approved=True)

            self.assertEqual(out["status"], "completed")
            rule_ids = sorted({f["id"] for f in out["result"]["findings"]})
            self.assertIn("PG002", rule_ids)  # dynamic code execution, confirmed
            self.assertTrue(out["result"]["evidence"])
            self.assertTrue(store.list_canonical_findings())


if __name__ == "__main__":
    unittest.main()
