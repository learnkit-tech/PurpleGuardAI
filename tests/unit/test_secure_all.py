import shutil
import tempfile
import unittest
from pathlib import Path

from scanner.developer.session import DeveloperSession


class TestSecureAll(unittest.TestCase):

    def setUp(self):
        self.source = Path("tests/vulnerable_app")
        self.temp_dir = Path(
            tempfile.mkdtemp(prefix="purpleguard_")
        )

        self.project = self.temp_dir / "project"

        shutil.copytree(
            self.source,
            self.project
        )

    def tearDown(self):
        shutil.rmtree(
            self.temp_dir,
            ignore_errors=True
        )

    def test_secure_all_requires_approval(self):
        session = DeveloperSession(self.project)

        before = session.scan()
        before_ids = [
            finding["id"]
            for finding in before["findings"]
        ]

        result = session.secure_all(
            approved=False
        )

        self.assertEqual(
            result["status"],
            "APPROVAL_REQUIRED"
        )

        after = session.scan()
        after_ids = [
            finding["id"]
            for finding in after["findings"]
        ]

        self.assertEqual(
            before_ids,
            after_ids
        )

    def test_secure_all_remediates_project(self):
        session = DeveloperSession(self.project)

        result = session.secure_all(
            approved=True
        )

        self.assertEqual(
            result["status"],
            "SECURE"
        )

        self.assertEqual(
            result["remaining"],
            []
        )

        final_scan = session.scan()

        self.assertEqual(
            final_scan["findings"],
            []
        )

    def test_secure_all_creates_backups(self):
        session = DeveloperSession(self.project)

        result = session.secure_all(
            approved=True
        )

        self.assertEqual(
            result["status"],
            "SECURE"
        )

        backups = list(
            self.project.rglob(
                "*.purpleguard.bak"
            )
        )

        self.assertGreaterEqual(
            len(backups),
            3
        )

    def test_already_secure_project(self):
        session = DeveloperSession(self.project)

        first = session.secure_all(
            approved=True
        )

        self.assertEqual(
            first["status"],
            "SECURE"
        )

        second = session.secure_all(
            approved=True
        )

        self.assertEqual(
            second["status"],
            "SECURE"
        )

        self.assertEqual(
            second["remaining"],
            []
        )

    def test_rollback_restores_vulnerable_source(self):
            session = DeveloperSession(self.project)

            result = session.secure_all(
                approved=True
            )

            self.assertEqual(
                result["status"],
                "SECURE"
            )

            secure_scan = session.scan()

            self.assertEqual(
                secure_scan["findings"],
                []
            )

            secrets_file = self.project / "secrets.py"

            rollback_result = session.remediation.rollback(
                secrets_file
            )

            self.assertEqual(
                rollback_result["status"],
                "ROLLED_BACK"
            )

            restored = secrets_file.read_text()

            self.assertIn(
                "sk_live_example_key",
                restored
            )

            self.assertIn(
                "example_token",
                restored
            )

            vulnerable_scan = session.scan()

            pg003 = [
                finding
                for finding in vulnerable_scan["findings"]
                if finding["id"] == "PG003"
            ]

            self.assertEqual(
                len(pg003),
                2
            )

if __name__ == "__main__":
    unittest.main()
