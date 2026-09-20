import unittest

from scanner.engine import SecurityScanner
from scanner.knowledge.loader import load_vulnerabilities
from scanner.reporting import enrich_findings
from scanner.remediation.patcher import CodePatcher
from hacker.planner import AttackPlanner
from hacker.validation.validator import LocalAttackValidator
from hacker.python_analyzer import analyze_python_file


def scan_code(filename, code):
    import os
    import tempfile

    with tempfile.TemporaryDirectory() as project:

        filepath = os.path.join(project, filename)

        with open(filepath, "w") as file:
            file.write(code)

        scanner = SecurityScanner(project)

        return scanner.scan()


def ids(results):
    return [
        item["id"]
        for item in results
    ]


class TestPG010Detection(unittest.TestCase):

    def test_detects_pickle_loads_on_variable(self):
        """pickle.loads(variable) must be flagged."""

        results = scan_code(
            "loader.py",
            'import pickle\n'
            'def load(data):\n'
            '    return pickle.loads(data)\n',
        )

        self.assertIn("PG010", ids(results))

    def test_detects_pickle_loads_from_request(self):
        """pickle.loads(request body data) must be flagged."""

        results = scan_code(
            "loader.py",
            'import pickle\n'
            'from flask import request\n'
            'data = request.get_data()\n'
            'obj = pickle.loads(data)\n',
        )

        self.assertIn("PG010", ids(results))

    def test_literal_payload_not_flagged(self):
        """
        A constant payload is developer-controlled, not
        attacker-controlled.
        """

        results = scan_code(
            "loader.py",
            'import pickle\n'
            'obj = pickle.loads(b"pickle-bytes")\n',
        )

        self.assertNotIn("PG010", ids(results))

    def test_json_loads_not_flagged(self):
        """json.loads is a safe, data-only parser."""

        results = scan_code(
            "loader.py",
            'import json\n'
            'def load(data):\n'
            '    return json.loads(data)\n',
        )

        self.assertNotIn("PG010", ids(results))

    def test_restricted_unpickler_not_flagged(self):
        """
        A RestrictedUnpickler's .load() is not a dotted pickle
        sink and must not be flagged.
        """

        results = scan_code(
            "loader.py",
            'import pickle\n'
            'class SafeUnpickler(pickle.Unpickler):\n'
            '    def find_class(self, module, name):\n'
            '        raise pickle.UnpicklingError("forbidden")\n'
            'obj = SafeUnpickler(stream).load()\n',
        )

        self.assertNotIn("PG010", ids(results))

    def test_hacker_analyzer_builds_deserialization_path(self):
        """The taint analyzer must produce a DESERIALIZATION path."""

        import os
        import tempfile

        code = (
            'import pickle\n'
            'from flask import request\n'
            'def load():\n'
            '    data = request.get_data()\n'
            '    return pickle.loads(data)\n'
        )

        with tempfile.TemporaryDirectory() as project:

            filepath = os.path.join(project, "loader.py")

            with open(filepath, "w") as file:
                file.write(code)

            result = analyze_python_file(filepath)

        categories = [
            path.category
            for path in result["paths"]
        ]

        self.assertIn("DESERIALIZATION", categories)


class TestPG010KnowledgeAndPlanning(unittest.TestCase):

    def test_knowledge_entry_exists(self):
        """PG010 must be planned, not silently dropped."""

        knowledge = load_vulnerabilities()

        self.assertIn("PG010", knowledge)

        entry = knowledge["PG010"]

        self.assertEqual(
            entry["name"],
            "Insecure Deserialization",
        )

        self.assertEqual(
            entry["severity"],
            "HIGH",
        )

    def test_enrich_findings_keeps_pg010(self):
        """enrich_findings must not drop PG010."""

        finding = {
            "id": "PG010",
            "file": "loader.py",
            "line": 3,
            "code": "pickle.loads(data)",
            "name": "Insecure Deserialization",
            "severity": "HIGH",
        }

        enriched = enrich_findings([finding])

        self.assertEqual(
            len(enriched),
            1,
        )

        self.assertEqual(
            enriched[0]["id"],
            "PG010",
        )

    def test_planner_maps_deserialization_to_validator(self):
        """DESERIALIZATION attack paths must plan to
        validate_deserialization."""

        plans = AttackPlanner().plan(
            [
                {
                    "id": "PATH-1",
                    "category": "DESERIALIZATION",
                    "severity": "HIGH",
                    "confidence": 0.9,
                }
            ]
        )

        self.assertEqual(
            len(plans),
            1,
        )

        self.assertEqual(
            plans[0].validator,
            "validate_deserialization",
        )


class TestPG010RemediationPolicy(unittest.TestCase):

    def test_pg010_has_no_auto_fix(self):
        """
        Safe deserialization remediation (RestrictedUnpickler or a
        data-format migration) is application-specific, so PG010
        must never be auto-fixed: the patcher must refuse and the
        finding stays for manual review.
        """

        self.assertNotIn(
            "PG010",
            CodePatcher.AUTO_FIXABLE,
        )

    def test_pg010_finding_not_auto_fixed(self):
        """Even a clean PG010 finding produces no patch."""

        finding = {
            "id": "PG010",
            "file": "nonexistent.py",
            "line": 3,
            "code": "pickle.loads(data)",
            "name": "Insecure Deserialization",
            "severity": "HIGH",
        }

        self.assertFalse(
            CodePatcher().can_auto_fix(finding)
        )


class TestPG010ValidatorContract(unittest.TestCase):

    def test_validate_deserialization_method_exists(self):
        """The runtime validator must expose validate_deserialization."""

        validator = LocalAttackValidator(
            "http://127.0.0.1:1"
        )

        self.assertTrue(
            callable(
                getattr(
                    validator,
                    "validate_deserialization",
                    None,
                )
            )
        )

    def test_validate_deserialization_reports_not_validated_on_dead_target(self):
        """
        Against an unreachable target the validator must report
        validated=False with evidence, never raise.
        """

        validator = LocalAttackValidator(
            "http://127.0.0.1:1"
        )

        result = validator.validate_deserialization()

        self.assertFalse(
            result["validated"]
        )

        self.assertIn(
            "payload",
            result,
        )

        self.assertIn(
            "evidence",
            result,
        )


if __name__ == "__main__":
    unittest.main()
