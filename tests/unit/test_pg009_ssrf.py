import unittest

from scanner.engine import SecurityScanner
from scanner.knowledge.loader import load_vulnerabilities
from scanner.reporting import enrich_findings
from scanner.remediation.patcher import CodePatcher
from hacker.planner import AttackPlanner
from hacker.validation.validator import LocalAttackValidator


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


class TestPG009Detection(unittest.TestCase):

    def test_detects_urlopen_with_tainted_url(self):
        """urlopen(url) from request input must be flagged."""

        results = scan_code(
            "fetcher.py",
            'import urllib.request\n'
            'def fetch(request):\n'
            '    url = request.args.get("url")\n'
            '    return urllib.request.urlopen(url, timeout=2)\n'
        )

        self.assertIn("PG009", ids(results))

    def test_detects_requests_get(self):
        """requests.get(url) from request input must be flagged."""

        results = scan_code(
            "fetcher.py",
            'import requests\n'
            'def fetch(request):\n'
            '    url = request.args.get("url")\n'
            '    return requests.get(url)\n'
        )

        self.assertIn("PG009", ids(results))

    def test_literal_url_not_flagged(self):
        """A constant URL is developer-controlled."""

        results = scan_code(
            "fetcher.py",
            'import urllib.request\n'
            'def fetch():\n'
            '    return urllib.request.urlopen("https://example.com/api")\n'
        )

        self.assertNotIn("PG009", ids(results))

    def test_allowlisted_url_not_flagged(self):
        """A startswith-allowlist guard must suppress the finding."""

        results = scan_code(
            "fetcher.py",
            'import urllib.request\n'
            'def fetch(request):\n'
            '    url = request.args.get("url")\n'
            '    if not url.startswith("https://api.trusted.example"):\n'
            '        raise ValueError("blocked")\n'
            '    return urllib.request.urlopen(url, timeout=2)\n'
        )

        self.assertNotIn("PG009", ids(results))

    def test_compound_allowlist_guard_not_flagged(self):
        """
        A compound guard (empty-check OR allowlist) must also
        suppress the finding: `if not url or not url.startswith(...)`
        is a valid destination allowlist.
        """

        results = scan_code(
            "fetcher.py",
            'import urllib.request\n'
            'ALLOWED = "https://api.internal.example"\n'
            'def fetch(request):\n'
            '    url = request.args.get("url")\n'
            '    if not url or not url.startswith(ALLOWED):\n'
            '        raise ValueError("SSRF blocked")\n'
            '    response = urllib.request.urlopen(url, timeout=2)\n'
            '    return response.status\n'
        )

        self.assertNotIn("PG009", ids(results))

    def test_unrelated_call_not_flagged(self):
        """Non-request calls must not trip the rule."""

        results = scan_code(
            "fetcher.py",
            'def fetch(request):\n'
            '    url = request.args.get("url")\n'
            '    return open(url)\n'
        )

        self.assertNotIn("PG009", ids(results))


class TestPG009KnowledgeAndPlanning(unittest.TestCase):

    def test_knowledge_entry_exists(self):
        """PG009 must be planned, not silently dropped."""

        knowledge = load_vulnerabilities()

        self.assertIn("PG009", knowledge)

        entry = knowledge["PG009"]

        self.assertEqual(
            entry["name"],
            "SSRF",
        )

        self.assertEqual(
            entry["severity"],
            "HIGH",
        )

    def test_enrich_findings_keeps_pg009(self):
        """enrich_findings must not drop PG009."""

        finding = {
            "id": "PG009",
            "file": "fetcher.py",
            "line": 3,
            "code": "urlopen(url)",
            "name": "SSRF",
            "severity": "HIGH",
        }

        enriched = enrich_findings([finding])

        self.assertEqual(
            len(enriched),
            1,
        )

        self.assertEqual(
            enriched[0]["id"],
            "PG009",
        )

    def test_planner_maps_ssrf_to_validator(self):
        """SSRF attack paths must plan to validate_ssrf."""

        plans = AttackPlanner().plan(
            [
                {
                    "id": "PATH-1",
                    "category": "SSRF",
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
            "validate_ssrf",
        )


class TestPG009RemediationPolicy(unittest.TestCase):

    def test_pg009_has_no_auto_fix(self):
        """
        SSRF allowlists are application-specific, so PG009 must
        never be auto-fixed: the patcher must refuse and the
        finding stays for manual review.
        """

        self.assertNotIn(
            "PG009",
            CodePatcher.AUTO_FIXABLE,
        )

    def test_pg009_finding_not_auto_fixed(self):
        """Even a clean PG009 finding produces no patch."""

        finding = {
            "id": "PG009",
            "file": "nonexistent.py",
            "line": 3,
            "code": "urlopen(url)",
            "name": "SSRF",
            "severity": "HIGH",
        }

        self.assertFalse(
            CodePatcher().can_auto_fix(finding)
        )


class TestPG009ValidatorContract(unittest.TestCase):

    def test_validate_ssrf_method_exists(self):
        """The runtime validator must expose validate_ssrf."""

        validator = LocalAttackValidator(
            "http://127.0.0.1:1"
        )

        self.assertTrue(
            callable(
                getattr(
                    validator,
                    "validate_ssrf",
                    None,
                )
            )
        )

    def test_validate_ssrf_reports_not_validated_on_dead_target(self):
        """
        Against an unreachable target the validator must report
        validated=False with evidence, never raise.
        """

        validator = LocalAttackValidator(
            "http://127.0.0.1:1"
        )

        result = validator.validate_ssrf()

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
