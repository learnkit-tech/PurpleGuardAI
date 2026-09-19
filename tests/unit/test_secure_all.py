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

        # The fixture contains one deliberately unprovable PG006
        # shape (a bare open() with no base directory), which the
        # planner must leave as a finding requiring review instead
        # of silently rewriting it.
        self.assertEqual(
            result["status"],
            "PARTIALLY_SECURED"
        )

        for finding_id in (
            "PG002",
            "PG003",
            "PG004",
        ):
            self.assertIn(
                finding_id,
                result["fixed"]
            )

        self.assertEqual(
            result["remaining"],
            ["PG006"]
        )

        review_ids = [
            finding["id"]
            for finding in result["requires_review"]
        ]

        self.assertEqual(
            review_ids,
            ["PG006"]
        )

        final_scan = session.scan()

        self.assertEqual(
            [
                finding["id"]
                for finding in final_scan["findings"]
            ],
            ["PG006"]
        )

    def test_secure_all_creates_backups(self):
        session = DeveloperSession(self.project)

        result = session.secure_all(
            approved=True
        )

        self.assertEqual(
            result["status"],
            "PARTIALLY_SECURED"
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
            "PARTIALLY_SECURED"
        )

        self.first_backups = list(
            self.project.rglob(
                "*.purpleguard.bak"
            )
        )

        # A second run must be a no-op: the only remaining finding
        # is the unprovable PG006 shape, which stays in the review
        # queue without touching any files again.
        second = session.secure_all(
            approved=True
        )

        self.assertEqual(
            second["status"],
            "REVIEW_REQUIRED"
        )

        self.assertEqual(
            second["fixed"],
            []
        )

        self.assertEqual(
            second["remaining"],
            first["remaining"]
        )

        # The second run creates no new backups: no file is
        # touched when nothing is auto-fixable.
        self.assertEqual(
            list(
                self.project.rglob(
                    "*.purpleguard.bak"
                )
            ),
            self.first_backups
        )

    def test_rollback_restores_vulnerable_source(self):
            session = DeveloperSession(self.project)

            result = session.secure_all(
                approved=True
            )

            self.assertEqual(
                result["status"],
                "PARTIALLY_SECURED"
            )

            secure_scan = session.scan()

            self.assertEqual(
                [
                    finding["id"]
                    for finding in secure_scan["findings"]
                ],
                ["PG006"]
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
