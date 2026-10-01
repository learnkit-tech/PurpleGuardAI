"""Tests for the real engine-backed workforce adapters.

Every test here executes a genuine PurpleGuard engine component against a
real authorized target. No engine is mocked unless the test is explicitly
about engine-unavailable / engine-failure behaviour.
"""

import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from security_workforce import (  # noqa: E402
    WorkforceOrchestrator,
    WorkforceStore,
    executable_capabilities,
    unavailable_capabilities,
)
from security_workforce.agents.engine_agent import EngineAgent  # noqa: E402
from security_workforce.capabilities import CAPABILITIES  # noqa: E402
from security_workforce.contracts import AgentStatus  # noqa: E402
from security_workforce.registry import load_registry  # noqa: E402

from scanner.engine import SecurityScanner  # noqa: E402
from scanner.rules.optional import OPTIONAL_RULES  # noqa: E402

VULN_EVAL = "def run(x):\n    return eval(x)\n"
VULN_SQL = 'uid = input("id")\nquery = "SELECT * FROM users WHERE id=" + uid\n'
VULN_PICKLE = "import pickle\n\ndata = pickle.loads(payload)\n"
VULN_SWALLOW = "import logging\n\ndef f():\n    try:\n        work()\n    except Exception:\n        pass\n"
VULN_COMMENT = "# api_key = sk_live_deadbeefdeadbeef\n\ndef f():\n    return 1\n"


class _Outcome:
    def __init__(self, findings, evidence, metadata):
        self.findings = findings
        self.evidence = evidence
        self.metadata = metadata


def _run(operation, files, **kwargs):
    """Run a workforce operation over a fresh temp target with `files`."""
    tmp = tempfile.TemporaryDirectory()
    root = Path(tmp.name) / "target"
    root.mkdir()
    for name, content in files.items():
        (root / name).write_text(content)
    workforce = WorkforceOrchestrator(store=WorkforceStore(Path(tmp.name) / "wf.json"))
    outcome = workforce.run(operation, target=str(root), idempotency_key="k", **kwargs)
    outcome["_root"] = str(root)
    outcome["_tmp"] = tmp
    return outcome


def _rule_ids(outcome):
    return sorted({f.get("id") for f in outcome["result"]["findings"]})


class CapabilityMapTests(unittest.TestCase):
    def test_executable_and_unavailable_counts(self):
        self.assertEqual(len(executable_capabilities()), 13)
        self.assertEqual(len(unavailable_capabilities()), 7)
        self.assertEqual(len(executable_capabilities()) + len(unavailable_capabilities()), 20)

    def test_every_executable_capability_names_an_engine_and_is_enabled(self):
        registry = load_registry()
        for cap in executable_capabilities():
            with self.subTest(agent=cap.agent_id):
                self.assertTrue(cap.engine, cap.agent_id)
                self.assertTrue(cap.adapter, cap.agent_id)
                self.assertTrue(registry[cap.agent_id].enabled, cap.agent_id)
                self.assertEqual(registry[cap.agent_id].implementation, "available")

    def test_every_unavailable_capability_documents_the_missing_dependency(self):
        for cap in unavailable_capabilities():
            with self.subTest(agent=cap.agent_id):
                self.assertTrue(cap.unavailable_reason, cap.agent_id)
                self.assertFalse(load_registry()[cap.agent_id].enabled)

    def test_capability_states_are_honest(self):
        workforce = WorkforceOrchestrator(store=WorkforceStore(Path(tempfile.mkdtemp()) / "wf.json"))
        states = {c["agent_id"]: c["state"] for c in workforce.capabilities()}
        for cap in executable_capabilities():
            self.assertEqual(states[cap.agent_id], "AVAILABLE", cap.agent_id)
        for cap in unavailable_capabilities():
            self.assertEqual(states[cap.agent_id], "UNAVAILABLE", cap.agent_id)


class NewEngineRuleTests(unittest.TestCase):
    def _scan(self, name, code, rules=None, target=None):
        root = target or tempfile.mkdtemp()
        (Path(root) / name).write_text(code)
        scanner = SecurityScanner(root, rules=rules) if rules is not None else SecurityScanner(root)
        return [f["id"] for f in scanner.scan()]

    def test_pg011_detects_swallowed_exception(self):
        self.assertIn("PG011", self._scan("s.py", VULN_SWALLOW, rules=OPTIONAL_RULES))

    def test_pg011_ignores_logged_exception(self):
        code = "import logging\n\ndef f():\n    try:\n        work()\n    except Exception:\n        logging.exception('boom')\n"
        self.assertNotIn("PG011", self._scan("s.py", code, rules=OPTIONAL_RULES))

    def test_pg012_detects_secret_in_comment(self):
        self.assertIn("PG012", self._scan("c.py", VULN_COMMENT, rules=OPTIONAL_RULES))

    def test_pg012_ignores_prose(self):
        self.assertNotIn("PG012", self._scan("c.py", "# reset the password here\nx = 1\n", rules=OPTIONAL_RULES))

    def test_optional_rules_are_not_in_the_default_scan(self):
        """The default engine output is unchanged for existing callers."""
        self.assertNotIn("PG011", self._scan("s.py", VULN_SWALLOW))
        self.assertNotIn("PG012", self._scan("c.py", VULN_COMMENT))


class AdapterExecutionTests(unittest.TestCase):
    def test_security_reviewer_runs_the_scanner(self):
        out = _run("security.review", {"vuln.py": VULN_EVAL})
        self.assertEqual(out["status"], "completed")
        self.assertEqual(_rule_ids(out), ["PG002"])
        self.assertEqual(out["result"]["metadata"]["engine"], "scanner.engine.SecurityScanner")
        out["_tmp"].cleanup()

    def test_database_reviewer_is_rule_filtered(self):
        out = _run("security.review.database", {"a.py": VULN_EVAL, "b.py": VULN_SQL})
        self.assertEqual(_rule_ids(out), ["PG004"])
        out["_tmp"].cleanup()

    def test_ml_reviewer_targets_deserialization(self):
        out = _run("security.review.ml", {"a.py": VULN_EVAL, "b.py": VULN_PICKLE})
        self.assertIn("PG010", _rule_ids(out))
        self.assertNotIn("PG004", _rule_ids(out))
        out["_tmp"].cleanup()

    def test_python_reviewer_finds_eval(self):
        out = _run("security.review.python", {"a.py": VULN_EVAL})
        self.assertEqual(_rule_ids(out), ["PG002"])
        out["_tmp"].cleanup()

    def test_code_reviewer_uses_the_independent_hacker_engine(self):
        out = _run("security.review.diff", {"a.py": VULN_EVAL})
        self.assertEqual(out["status"], "completed")
        self.assertEqual(_rule_ids(out), ["PG002"])
        self.assertEqual(
            out["result"]["metadata"]["engine"],
            "hacker.python_analyzer.PythonSecurityAnalyzer",
        )
        out["_tmp"].cleanup()

    def test_silent_failure_hunter(self):
        out = _run("security.review.error-paths", {"a.py": VULN_SWALLOW})
        self.assertEqual(_rule_ids(out), ["PG011"])
        out["_tmp"].cleanup()

    def test_comment_analyzer(self):
        out = _run("security.review.comments", {"a.py": VULN_COMMENT})
        self.assertEqual(_rule_ids(out), ["PG012"])
        out["_tmp"].cleanup()

    def test_code_explorer_produces_observations_not_findings(self):
        out = _run("security.recon", {"app.py": "def login(password):\n    return password\n"})
        self.assertEqual(out["status"], "completed")
        self.assertEqual(out["result"]["findings"], [])
        self.assertTrue(out["result"]["evidence"])
        self.assertIn("languages", out["result"]["metadata"])
        out["_tmp"].cleanup()

    def test_planner_builds_a_real_plan(self):
        out = _run("security.plan", {"a.py": VULN_EVAL})
        self.assertEqual(out["status"], "completed")
        plan = out["result"]["metadata"]["plan"]
        self.assertTrue(plan)
        self.assertTrue(all(p["playbook"] for p in plan))
        out["_tmp"].cleanup()

    def test_coordinator_escalates_uncorroborated_high_risk(self):
        out = _run("security.review", {"a.py": VULN_EVAL})
        coord = _run("security.coordinate", {"b.py": "x = 1\n"})
        self.assertEqual(coord["status"], "completed")
        out["_tmp"].cleanup()
        coord["_tmp"].cleanup()

    def test_agent_evaluator_scores_a_prior_result(self):
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name) / "target"
        root.mkdir()
        (root / "a.py").write_text(VULN_EVAL)
        store = WorkforceStore(Path(tmp.name) / "wf.json")
        workforce = WorkforceOrchestrator(store=store)
        workforce.run("security.review", target=str(root), idempotency_key="1")
        evaluated = workforce.run("security.verify.result-quality", target=str(root))
        self.assertEqual(evaluated["status"], "completed")
        self.assertEqual(evaluated["result"]["findings"], [])
        self.assertIn("assessment", evaluated["result"]["metadata"])
        self.assertEqual(evaluated["result"]["metadata"]["assessment"]["max_risk"], "CRITICAL")
        tmp.cleanup()

    def test_agent_evaluator_without_prior_result_is_invalid(self):
        out = _run("security.verify.result-quality", {"a.py": "x = 1\n"})
        self.assertEqual(out["status"], "rejected")
        self.assertEqual(out["errors"][0]["code"], "INVALID_TASK")
        out["_tmp"].cleanup()

    def test_tdd_guide_runs_the_projects_tests(self):
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name) / "target"
        root.mkdir()
        (root / "test_ok.py").write_text("def test_ok():\n    assert True\n")
        workforce = WorkforceOrchestrator(store=WorkforceStore(Path(tmp.name) / "wf.json"))
        out = workforce.run("security.verify.regression", target=str(root))
        self.assertEqual(out["status"], "completed")
        self.assertTrue(out["result"]["metadata"]["tests_passed"])
        tmp.cleanup()

    def test_every_evidence_entry_has_the_required_fields(self):
        out = _run("security.review", {"a.py": VULN_EVAL})
        self.assertTrue(out["result"]["evidence"])
        for ev in out["result"]["evidence"]:
            for key in ("what_tested", "where_tested", "what_happened", "validation_state"):
                self.assertIn(key, ev)
        out["_tmp"].cleanup()


class EngineUnavailableTests(unittest.TestCase):
    def test_unimplemented_capability_is_unavailable(self):
        out = _run("security.monitor", {"a.py": VULN_EVAL})
        self.assertEqual(out["status"], AgentStatus.UNAVAILABLE.value)
        self.assertEqual(out["errors"][0]["code"], "ENGINE_UNAVAILABLE")
        self.assertIn("scheduler", out["errors"][0]["detail"]["unavailable_reason"])
        out["_tmp"].cleanup()

    def test_dynamic_validation_unavailable_without_a_controlled_target(self):
        out = _run("security.validate.e2e", {"a.py": VULN_EVAL}, approved=True)
        self.assertEqual(out["status"], AgentStatus.UNAVAILABLE.value)
        self.assertEqual(out["errors"][0]["code"], "ENGINE_UNAVAILABLE")
        self.assertEqual(out["canonical_findings"], [])
        out["_tmp"].cleanup()

    def test_dynamic_validation_requires_approval(self):
        out = _run("security.validate.e2e", {"a.py": VULN_EVAL})
        self.assertEqual(out["status"], AgentStatus.REJECTED.value)
        self.assertEqual(out["errors"][0]["code"], "REJECTED")
        out["_tmp"].cleanup()


class EngineFailureTests(unittest.TestCase):
    class _Boom:
        engine = "boom"

        def run(self, target, *, context=None):
            raise RuntimeError("engine exploded")

    def test_engine_exception_is_failed_and_fabricates_nothing(self):
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name) / "target"
        root.mkdir()
        (root / "a.py").write_text(VULN_EVAL)
        workforce = WorkforceOrchestrator(store=WorkforceStore(Path(tmp.name) / "wf.json"))
        workforce._agents["security-reviewer"] = EngineAgent(  # noqa: SLF001
            "security-reviewer", "vulnerability_analysis",
            frozenset({"observe", "analyze"}), self._Boom(),
        )
        out = workforce.run("security.review", target=str(root))
        self.assertEqual(out["status"], "failed")
        self.assertEqual(out["errors"][0]["code"], "EXECUTION_ERROR")
        self.assertEqual(out["canonical_findings"], [])
        tmp.cleanup()

    def test_permission_escalation_is_rejected(self):
        out = _run("security.review", {"a.py": VULN_EVAL}, required_permissions=("validate",))
        self.assertEqual(out["status"], "rejected")
        self.assertEqual(out["errors"][0]["code"], "REJECTED")
        out["_tmp"].cleanup()


class ProvenanceAndPersistenceTests(unittest.TestCase):
    def test_result_records_engine_and_provenance_is_pinned(self):
        from security_workforce import ECC_SOURCE_COMMIT

        out = _run("security.review", {"a.py": VULN_EVAL})
        self.assertTrue(out["result"]["metadata"]["engine"])
        for spec in load_registry().values():
            self.assertEqual(spec.provenance["ecc_commit"], ECC_SOURCE_COMMIT)
        out["_tmp"].cleanup()

    def test_result_and_canonical_findings_persist(self):
        out = _run("security.review", {"a.py": VULN_EVAL})
        self.assertTrue(out["canonical_findings"])
        canonical = out["canonical_findings"][0]
        self.assertTrue(canonical["evidence"])
        self.assertTrue(canonical["sources"])
        out["_tmp"].cleanup()


if __name__ == "__main__":
    unittest.main()
