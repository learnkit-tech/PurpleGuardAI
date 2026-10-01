"""Tests for the PurpleGuard Security Agent Workforce (security_workforce)."""

import re
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from security_workforce import (  # noqa: E402
    ECC_SOURCE_COMMIT,
    ContextBuilder,
    WorkforceOrchestrator,
    WorkforceStore,
    correlate_results,
    evaluate_result,
    executable_capabilities,
    fingerprint,
    get_playbook,
    load_playbooks,
    load_registry,
    unavailable_capabilities,
    validate_registry,
)
from security_workforce.contracts import AgentResult, AgentStatus  # noqa: E402

VULN_SOURCE = "import os\n\ndef run(x):\n    return eval(x)\n\nos.system('ping ' + x)\n"

RESULT_KEYS = {
    "agent_id", "task_id", "correlation_id", "role", "status",
    "findings", "evidence", "recommendations", "confidence", "errors", "metadata",
}
ENVELOPE_KEYS = {
    "task_id", "correlation_id", "operation", "project_id", "playbook",
    "status", "result", "evaluation", "canonical_findings", "errors", "metadata",
}


class _MalformedAgent:
    def execute(self, task, *, target, context=None):
        return {"not": "an AgentResult"}


class _ExplodingAgent:
    def execute(self, task, *, target, context=None):
        raise RuntimeError("boom")


class RegistryAndPlaybookTests(unittest.TestCase):
    def test_registry_loads_and_validates(self):
        registry = load_registry()
        self.assertEqual(len(registry), 20)
        self.assertEqual(validate_registry(), [])
        self.assertIn("security-reviewer", registry)

    def test_enabled_agents_are_exactly_the_executable_capabilities(self):
        enabled = {s.agent_id for s in load_registry().values() if s.enabled}
        executable = {cap.agent_id for cap in executable_capabilities()}
        self.assertEqual(enabled, executable)
        # Every enabled agent must declare itself available (no silent gaps).
        for spec in load_registry().values():
            if spec.enabled:
                self.assertEqual(spec.implementation, "available", spec.agent_id)

    def test_unavailable_agents_are_disabled_and_never_available(self):
        for cap in unavailable_capabilities():
            spec = load_registry()[cap.agent_id]
            self.assertFalse(spec.enabled, cap.agent_id)
            self.assertNotEqual(spec.implementation, "available", cap.agent_id)
            self.assertTrue(cap.unavailable_reason, cap.agent_id)

    def test_no_agent_may_hold_modify(self):
        for spec in load_registry().values():
            self.assertNotIn("modify", spec.permissions)

    def test_every_agent_has_ecc_provenance(self):
        for spec in load_registry().values():
            self.assertTrue(spec.provenance.get("ecc_source", "").startswith("ecc/agents/"))

    def test_playbooks_load_and_validate(self):
        playbooks = load_playbooks()
        self.assertEqual(len(playbooks), 5)
        self.assertIn("security.static_review", playbooks)
        self.assertIsNotNone(get_playbook("security.validate_finding"))


class OrchestratorTestBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.target = Path(self._tmp.name) / "target"
        self.target.mkdir()
        self.vuln_file = self.target / "vuln.py"
        self.vuln_file.write_text(VULN_SOURCE)
        self.workforce = WorkforceOrchestrator(
            store=WorkforceStore(Path(self._tmp.name) / "wf.json")
        )


class RoutingAndTaskTests(OrchestratorTestBase):
    def test_select_routes_known_operation(self):
        selected = self.workforce.select("security.review")
        self.assertEqual(selected["agent_id"], "security-reviewer")

    def test_unknown_operation_rejected(self):
        out = self.workforce.run("does.not.exist", target=str(self.target))
        self.assertEqual(out["status"], AgentStatus.REJECTED.value)
        self.assertEqual(out["errors"][0]["code"], "UNSUPPORTED_OPERATION")

    def test_task_ids_deterministic(self):
        a = self.workforce.run("security.review", target=str(self.target), idempotency_key="k1")
        b = self.workforce.run("security.review", target=str(self.target), idempotency_key="k1")
        c = self.workforce.run("security.review", target=str(self.target), idempotency_key="k2")
        self.assertEqual(a["task_id"], b["task_id"])
        self.assertEqual(a["correlation_id"], b["correlation_id"])
        self.assertNotEqual(a["task_id"], c["task_id"])

    def test_result_and_canonical_persistence(self):
        out = self.workforce.run("security.review", target=str(self.target), idempotency_key="p1")
        self.assertIsNotNone(self.workforce.result(out["task_id"]))
        self.assertTrue(self.workforce.results())
        self.assertTrue(self.workforce.canonical_findings())
        self.assertIsNone(self.workforce.result("pgtask-nope"))


class ResultContractTests(OrchestratorTestBase):
    def test_envelope_and_result_contract(self):
        out = self.workforce.run("security.review", target=str(self.target), idempotency_key="c1")
        self.assertEqual(set(out), ENVELOPE_KEYS)
        self.assertEqual(set(out["result"]), RESULT_KEYS)
        self.assertEqual(out["result"]["status"], AgentStatus.COMPLETED.value)
        self.assertEqual(out["result"]["agent_id"], "security-reviewer")

    def test_evidence_requirements_present(self):
        out = self.workforce.run("security.review", target=str(self.target), idempotency_key="e1")
        self.assertTrue(out["result"]["evidence"])
        first = out["result"]["evidence"][0]
        for key in ("what_tested", "where_tested", "what_happened", "validation_state"):
            self.assertIn(key, first)
        self.assertEqual(first["file"] if "file" in first else "vuln.py", "vuln.py")

    def test_canonical_findings_are_deduplicated_and_evidenced(self):
        out = self.workforce.run("security.review", target=str(self.target), idempotency_key="d1")
        rule_ids = [c["rule_id"] for c in out["canonical_findings"]]
        self.assertEqual(sorted(rule_ids), ["PG002", "PG005"])
        # re-running does not create duplicate canonical findings
        self.workforce.run("security.review", target=str(self.target), idempotency_key="d2")
        self.assertEqual(len(self.workforce.canonical_findings()), 2)
        self.assertTrue(all(c["evidence"] for c in out["canonical_findings"]))


class EvaluationTests(OrchestratorTestBase):
    def test_critical_result_requires_validation(self):
        out = self.workforce.run("security.review", target=str(self.target), idempotency_key="v1")
        assessment = out["evaluation"]
        self.assertEqual(assessment["axes"]["evidence_quality"], 1.0)
        self.assertTrue(assessment["requires_validation"])
        self.assertFalse(assessment["authoritative"])
        self.assertEqual(assessment["max_risk"], "CRITICAL")

    def test_clean_target_is_authoritative(self):
        clean = Path(self._tmp.name) / "clean"
        clean.mkdir()
        (clean / "ok.py").write_text("def add(a, b):\n    return a + b\n")
        out = self.workforce.run("security.review", target=str(clean), idempotency_key="clean1")
        self.assertEqual(out["result"]["findings"], [])
        self.assertTrue(out["evaluation"]["authoritative"])
        self.assertFalse(out["evaluation"]["requires_validation"])

    def test_evaluate_result_on_failure(self):
        assessment = evaluate_result({"status": "failed", "findings": [], "confidence": 0.0})
        self.assertFalse(assessment["authoritative"])

    def test_evaluate_import_is_not_circular(self):
        # guard against evaluation<->correlation import cycles
        self.assertTrue(callable(evaluate_result))


class CorrelationTests(unittest.TestCase):
    def _result(self, agent_id, severity="HIGH"):
        finding = {"id": "PG002", "name": "Dangerous eval()", "severity": severity,
                   "category": "Code Injection", "file": "/x/a.py", "line": 4, "code": "eval(x)"}
        return {
            "agent_id": agent_id, "task_id": f"t-{agent_id}", "correlation_id": f"c-{agent_id}",
            "status": "completed",
            "findings": [finding],
            "evidence": [{"where_tested": "a.py:4", "what_tested": "x"}],
        }

    def test_fingerprint_is_stable(self):
        finding = {"id": "PG002", "file": "/x/a.py", "line": 4, "code": "eval(x)"}
        self.assertEqual(fingerprint(finding), fingerprint(dict(finding)))

    def test_multiple_agents_corroborate_one_finding(self):
        canonical = correlate_results([self._result("security-reviewer"), self._result("python-reviewer")])
        self.assertEqual(len(canonical), 1)
        self.assertEqual(canonical[0]["validation_state"], "corroborated")
        self.assertEqual(len(canonical[0]["sources"]), 2)

    def test_single_agent_finding_stays_unvalidated(self):
        canonical = correlate_results([self._result("security-reviewer")])
        self.assertEqual(canonical[0]["validation_state"], "unvalidated")


class FailureAndBoundaryTests(OrchestratorTestBase):
    def test_bad_target_rejected(self):
        out = self.workforce.run("security.review", target="/no/such/dir")
        self.assertEqual(out["status"], AgentStatus.REJECTED.value)
        self.assertEqual(out["errors"][0]["code"], "INVALID_TASK")

    def test_unavailable_agent(self):
        workforce = WorkforceOrchestrator(
            store=WorkforceStore(Path(self._tmp.name) / "u.json"),
            agents={"security-reviewer": None},
        )
        out = workforce.run("security.review", target=str(self.target))
        self.assertEqual(out["status"], AgentStatus.UNAVAILABLE.value)
        self.assertEqual(out["errors"][0]["code"], "ECC_UNAVAILABLE")

    def test_malformed_result_normalized(self):
        workforce = WorkforceOrchestrator(
            store=WorkforceStore(Path(self._tmp.name) / "m.json"),
            agents={"security-reviewer": _MalformedAgent()},
        )
        out = workforce.run("security.review", target=str(self.target))
        self.assertEqual(out["status"], AgentStatus.FAILED.value)
        self.assertEqual(out["errors"][0]["code"], "MALFORMED_RESULT")

    def test_adapter_exception_normalized(self):
        workforce = WorkforceOrchestrator(
            store=WorkforceStore(Path(self._tmp.name) / "x.json"),
            agents={"security-reviewer": _ExplodingAgent()},
        )
        out = workforce.run("security.review", target=str(self.target))
        self.assertEqual(out["errors"][0]["code"], "EXECUTION_ERROR")

    def test_permission_escalation_rejected(self):
        out = self.workforce.run(
            "security.review", target=str(self.target), required_permissions=("modify",)
        )
        self.assertEqual(out["status"], AgentStatus.REJECTED.value)
        self.assertEqual(out["errors"][0]["code"], "REJECTED")
        self.assertIn("modify", out["errors"][0]["detail"]["missing_permissions"])

    def test_review_does_not_modify_source(self):
        before = self.vuln_file.read_bytes()
        self.workforce.run("security.review", target=str(self.target))
        self.assertEqual(self.vuln_file.read_bytes(), before)


class ContextTests(OrchestratorTestBase):
    def test_context_scopes_and_history(self):
        builder = ContextBuilder(WorkforceStore(Path(self._tmp.name) / "ctx.json"))
        first = builder.build(project_id="purpleguard", target=str(self.target))
        self.assertIn("project", first.keys())
        self.assertEqual(first.project_context["target"], str(self.target))

    def test_context_tracks_previous_results(self):
        self.workforce.run("security.review", target=str(self.target), idempotency_key="h1")
        builder = ContextBuilder(self.workforce._store)  # noqa: SLF001 (test)
        bundle = builder.build(project_id="purpleguard", target=str(self.target))
        self.assertGreaterEqual(bundle.historical_context["previous_result_count"], 1)


class CapabilityMapTests(unittest.TestCase):
    CATEGORIES = {
        "reconnaissance", "vulnerability_analysis", "attack_path_analysis",
        "validation", "monitoring", "remediation", "verification", "orchestration",
    }

    def test_every_agent_role_is_a_known_category(self):
        for spec in load_registry().values():
            self.assertIn(spec.role, self.CATEGORIES)

    def test_playbook_participants_exist_in_registry(self):
        registry = load_registry()
        for playbook in load_playbooks().values():
            for agent_id in playbook.get("participating_agents", []):
                if agent_id == "purpleguard-orchestrator":
                    continue  # the orchestrator itself, not a registry agent
                self.assertIn(agent_id, registry, f"unknown agent in {playbook['playbook_id']}")

    def test_playbooks_declare_an_approval_gate(self):
        for playbook in load_playbooks().values():
            self.assertIn("approval_gate", playbook)


class ProvenanceAndBoundaryTests(unittest.TestCase):
    def test_registry_provenance_pins_the_ecc_commit(self):
        for spec in load_registry().values():
            self.assertEqual(spec.provenance.get("ecc_commit"), ECC_SOURCE_COMMIT)

    def test_workforce_does_not_import_ecc(self):
        pattern = re.compile(r"^\s*(from\s+ecc(\.|\s)|import\s+ecc(\.|\s|$))", re.M)
        root = PROJECT_ROOT / "security_workforce"
        offenders = [
            str(path.relative_to(PROJECT_ROOT))
            for path in root.rglob("*.py")
            if pattern.search(path.read_text())
        ]
        self.assertEqual(offenders, [], f"workforce must not import ecc: {offenders}")

    def test_no_agent_declares_a_modify_capability(self):
        for spec in load_registry().values():
            self.assertNotIn("modify", spec.permissions)
            self.assertNotIn("modify", spec.capabilities)

    def test_no_fake_monitoring_timers(self):
        """Continuous assessment must not be faked with sleeps or timers."""
        for path in (PROJECT_ROOT / "security_workforce").rglob("*.py"):
            text = path.read_text()
            self.assertNotIn("time.sleep(", text, str(path))
            self.assertNotIn("threading.Timer", text, str(path))


class StoreIsolationTests(unittest.TestCase):
    def test_store_writes_only_its_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nested" / "wf.json"
            store = WorkforceStore(path)
            store.save_result({"task_id": "t1", "status": "completed"})
            self.assertTrue(path.is_file())
            self.assertEqual(store.get_result("t1")["status"], "completed")


if __name__ == "__main__":
    unittest.main()
