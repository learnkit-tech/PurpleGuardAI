import ast
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from scanner.engine import SecurityScanner
from scanner.knowledge.loader import load_vulnerabilities
from scanner.reporting import enrich_findings
from scanner.remediation.patcher import CodePatcher
from scanner.developer.session import DeveloperSession


class TestPG006Detection(unittest.TestCase):

    def scan_code(self, filename, code):
        with tempfile.TemporaryDirectory() as project:

            filepath = os.path.join(project, filename)

            with open(filepath, "w") as file:
                file.write(code)

            scanner = SecurityScanner(project)

            return scanner.scan()

    def ids(self, results):
        return [
            item["id"]
            for item in results
        ]

    def test_detects_base_dir_join(self):
        """The supported shape must be detected by PG006."""

        results = self.scan_code(
            "web.py",
            'from pathlib import Path\n'
            'BASE = Path(__file__).parent / "data"\n'
            'def read_report(filename):\n'
            '    target = BASE / filename\n'
            '    with open(target) as f:\n'
            '        return f.read()\n'
        )

        self.assertIn("PG006", self.ids(results))

    def test_detects_bare_open(self):
        """The unprovable shape must also be detected."""

        results = self.scan_code(
            "web.py",
            'def read_user_file(request):\n'
            '    filename = request.args.get("file")\n'
            '    with open(filename) as f:\n'
            '        return f.read()\n'
        )

        self.assertIn("PG006", self.ids(results))

    def test_constant_path_not_flagged(self):
        """A literal path is not attacker-controlled."""

        results = self.scan_code(
            "web.py",
            'with open("config.txt") as f:\n'
            '    pass\n'
        )

        self.assertNotIn("PG006", self.ids(results))

    def test_guarded_path_not_flagged(self):
        """The generated guard pattern must not re-flag."""

        results = self.scan_code(
            "web.py",
            'from pathlib import Path\n'
            'def read_report(filename, base_dir):\n'
            '    target = (base_dir / filename).resolve()\n'
            '    if not target.is_relative_to(base_dir.resolve()):\n'
            '        raise ValueError("blocked")\n'
            '    with open(target) as f:\n'
            '        return f.read()\n'
        )

        self.assertNotIn("PG006", self.ids(results))


class TestPG006KnowledgeAndPlanner(unittest.TestCase):

    def test_knowledge_entry_exists(self):
        """PG006 must be planned, not silently dropped."""

        knowledge = load_vulnerabilities()

        self.assertIn("PG006", knowledge)

        entry = knowledge["PG006"]

        self.assertEqual(
            entry["name"],
            "Path Traversal",
        )

        self.assertEqual(
            entry["category"],
            "Path Traversal",
        )

        self.assertEqual(
            entry["severity"],
            "HIGH",
        )

    def test_enrich_findings_keeps_pg006(self):
        """enrich_findings must not drop PG006 anymore."""

        finding = {
            "id": "PG006",
            "file": "web.py",
            "line": 3,
            "code": "open(filename)",
            "name": "Path Traversal",
            "severity": "HIGH",
        }

        enriched = enrich_findings([finding])

        self.assertEqual(
            len(enriched),
            1,
        )

        self.assertEqual(
            enriched[0]["id"],
            "PG006",
        )


class TestPG006StaticRemediation(unittest.TestCase):

    def setUp(self):
        self.project = Path(
            tempfile.mkdtemp(prefix="pg006_")
        )

    def tearDown(self):
        shutil.rmtree(
            self.project,
            ignore_errors=True,
        )

    def scan(self):
        scanner = SecurityScanner(
            str(self.project)
        )

        return enrich_findings(
            scanner.scan()
        )

    def test_supported_pattern_is_remediated_and_rescanned(self):
        """
        The supported shape gets a guard, the file is re-scanned,
        and the finding is gone: patched code is re-verified by the
        scanner, not trusted blindly.
        """

        module = self.project / "files.py"

        module.write_text(
            'from pathlib import Path\n'
            'BASE = Path(__file__).resolve().parent / "data"\n'
            'def read_report(filename):\n'
            '    target = BASE / filename\n'
            '    with open(target) as f:\n'
            '        return f.read()\n'
        )

        findings = self.scan()

        pg006 = [
            finding
            for finding in findings
            if finding["id"] == "PG006"
        ]

        self.assertEqual(
            len(pg006),
            1,
        )

        patcher = CodePatcher()

        with open(pg006[0]["file"]) as f:
            content = f.read()

        fixed = patcher._generate_actual_fix(
            pg006[0],
            content,
        )

        self.assertIsNotNone(fixed)

        compile(fixed, "files.py", "exec")

        module.write_text(fixed)

        rescanned = self.scan()

        self.assertEqual(
            rescanned,
            [],
        )

    def test_unsupported_pattern_is_left_for_manual_review(self):
        """
        A bare open(<param>) has no provable base directory, so no
        patch may be generated and the file must stay untouched.
        """

        module = self.project / "unsafe.py"

        original = (
            'def read_user_file(request):\n'
            '    filename = request.args.get("file")\n'
            '    with open(filename) as f:\n'
            '        return f.read()\n'
        )

        module.write_text(original)

        findings = self.scan()

        pg006 = [
            finding
            for finding in findings
            if finding["id"] == "PG006"
        ]

        self.assertEqual(
            len(pg006),
            1,
        )

        patcher = CodePatcher()

        with open(pg006[0]["file"]) as f:
            content = f.read()

        fixed = patcher._generate_actual_fix(
            pg006[0],
            content,
        )

        self.assertIsNone(fixed)

        patch_result = patcher.create_patch(
            pg006[0]
        )

        self.assertEqual(
            patch_result["status"],
            "NO_PATCH",
        )

        self.assertEqual(
            module.read_text(),
            original,
        )

    def test_untrusted_base_operand_is_not_transformed(self):
        """
        A join whose base operand contains user/request symbols is
        not provably trusted and must not be auto-fixed.
        """

        module = self.project / "shady.py"

        original = (
            'from pathlib import Path\n'
            'def read_report(filename, request):\n'
            '    base = request.args.get("base")\n'
            '    target = Path(base) / filename\n'
            '    with open(target) as f:\n'
            '        return f.read()\n'
        )

        module.write_text(original)

        findings = self.scan()

        pg006 = [
            finding
            for finding in findings
            if finding["id"] == "PG006"
        ]

        self.assertEqual(
            len(pg006),
            1,
        )

        patcher = CodePatcher()

        fixed = patcher._generate_actual_fix(
            pg006[0],
            module.read_text(),
        )

        self.assertIsNone(fixed)

        self.assertEqual(
            module.read_text(),
            original,
        )

    def test_in_function_file_derived_base_is_remediated(self):
        """
        The proven pattern from tests/hacker_target/app.py builds
        base_dir inside the function from __file__. That alias is
        provably trusted and must be remediated.
        """

        module = self.project / "viewer.py"

        module.write_text(
            'from pathlib import Path\n'
            'def read_report(filename):\n'
            '    base_dir = Path(__file__).resolve().parent / "reports"\n'
            '    target = base_dir / filename\n'
            '    with open(target) as f:\n'
            '        return f.read()\n'
        )

        findings = self.scan()

        pg006 = [
            finding
            for finding in findings
            if finding["id"] == "PG006"
        ]

        self.assertEqual(
            len(pg006),
            1,
        )

        patcher = CodePatcher()

        fixed = patcher._generate_actual_fix(
            pg006[0],
            module.read_text(),
        )

        self.assertIsNotNone(fixed)

        compile(fixed, "viewer.py", "exec")

        module.write_text(fixed)

        self.assertEqual(
            self.scan(),
            [],
        )

    def test_untrusted_module_level_base_stays_review(self):
        """
        A lowercase module-level variable has unknown provenance,
        so the join is not provably safe and stays for review.
        """

        module = self.project / "vague.py"

        original = (
            'from pathlib import Path\n'
            'base = get_base_dir()\n'
            'def read_report(filename):\n'
            '    target = base / filename\n'
            '    with open(target) as f:\n'
            '        return f.read()\n'
        )

        module.write_text(original)

        findings = self.scan()

        pg006 = [
            finding
            for finding in findings
            if finding["id"] == "PG006"
        ]

        self.assertEqual(
            len(pg006),
            1,
        )

        fixed = CodePatcher()._generate_actual_fix(
            pg006[0],
            module.read_text(),
        )

        self.assertIsNone(fixed)

        self.assertEqual(
            module.read_text(),
            original,
        )

    def test_secure_all_queues_unsupported_for_review(self):
        """
        secure_all must keep unprovable PG006 findings in the
        requires_review queue instead of silently rewriting them.
        """

        (self.project / "unsafe.py").write_text(
            'def read_user_file(request):\n'
            '    filename = request.args.get("file")\n'
            '    with open(filename) as f:\n'
            '        return f.read()\n'
        )

        session = DeveloperSession(
            self.project
        )

        result = session.secure_all(
            approved=True
        )

        self.assertIn(
            result["status"],
            ("REVIEW_REQUIRED", "PARTIALLY_SECURED"),
        )

        self.assertIn(
            "PG006",
            result["remaining"],
        )

        review_ids = [
            finding["id"]
            for finding in result["requires_review"]
        ]

        self.assertIn(
            "PG006",
            review_ids,
        )

        self.assertEqual(
            (self.project / "unsafe.py").read_text(),
            'def read_user_file(request):\n'
            '    filename = request.args.get("file")\n'
            '    with open(filename) as f:\n'
            '        return f.read()\n',
        )


class TestPG005PG007PG008Unchanged(unittest.TestCase):

    def setUp(self):
        self.project = Path(
            tempfile.mkdtemp(prefix="pg_regression_")
        )

    def tearDown(self):
        shutil.rmtree(
            self.project,
            ignore_errors=True,
        )

    def test_auto_fixable_set_is_unchanged(self):
        """PG006-010 join the set; no existing member is removed."""

        self.assertEqual(
            CodePatcher.AUTO_FIXABLE,
            frozenset(
                {
                    "PG001", "PG002", "PG003", "PG004",
                    "PG005", "PG006", "PG007", "PG008",
                    "PG009", "PG010",
                }
            ),
        )

    def test_pg005_command_injection_still_fixed(self):

        module = self.project / "cmd.py"

        module.write_text(
            'import os\n'
            'def ping(host):\n'
            '    os.system("ping " + host)\n'
        )

        session = DeveloperSession(
            self.project
        )

        result = session.secure_all(
            approved=True
        )

        self.assertEqual(
            result["status"],
            "SECURE",
        )

        self.assertNotIn(
            "PG005",
            result["remaining"],
        )

    def test_pg007_xss_still_fixed(self):

        module = self.project / "web.py"

        module.write_text(
            'from flask import Response\n'
            'def greet(request):\n'
            '    name = request.args.get("name")\n'
            '    return Response("<h1>Hello " + name + "</h1>")\n'
        )

        session = DeveloperSession(
            self.project
        )

        result = session.secure_all(
            approved=True
        )

        self.assertEqual(
            result["status"],
            "SECURE",
        )

        self.assertNotIn(
            "PG007",
            result["remaining"],
        )

    def test_pg008_open_redirect_still_fixed(self):

        module = self.project / "web.py"

        module.write_text(
            'from flask import redirect\n'
            'def go(request):\n'
            '    next_url = request.args.get("next")\n'
            '    return redirect(next_url)\n'
        )

        session = DeveloperSession(
            self.project
        )

        result = session.secure_all(
            approved=True
        )

        self.assertEqual(
            result["status"],
            "SECURE",
        )

        self.assertNotIn(
            "PG008",
            result["remaining"],
        )


if __name__ == "__main__":
    unittest.main()
