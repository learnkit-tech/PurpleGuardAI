import os
import tempfile
import unittest

from scanner.remediation.diff import generate_diff
from scanner.remediation.patcher import CodePatcher


class TestPatchGenerator(unittest.TestCase):

    def test_patch_creation(self):
        patch = generate_diff(
            'password = "admin123"',
            'password = os.getenv("APP_PASSWORD")'
        )

        self.assertIn(
            '-password = "admin123"',
            patch
        )

        self.assertIn(
            '+password = os.getenv("APP_PASSWORD")',
            patch
        )

    def test_pg003_patch_removes_hardcoded_secret(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "secrets.py")

            with open(filepath, "w") as file:
                file.write(
                    'API_KEY = "secret_value"\n'
                    'TOKEN = "example_token"\n'
                )

            finding = {
                "id": "PG003",
                "file": filepath,
                "line": 1,
                "code": 'API_KEY = "secret_value"',
                "remediation": {
                    "before": 'API_KEY = "secret_value"',
                    "after": (
                        'import os\n'
                        'API_KEY = os.getenv("API_KEY")'
                    )
                }
            }

            result = CodePatcher().create_patch(finding)

            self.assertEqual(result["status"], "READY")

            self.assertIn(
                '+API_KEY = os.getenv("API_KEY")',
                result["patch"]
            )

    def test_pg004_patch_contains_replacement(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "sql_test.py")

            with open(filepath, "w") as file:
                file.write(
                    'user_id = input("ID: ")\n'
                    '\n'
                    'query = "SELECT * FROM users WHERE id=" + user_id\n'
                )

            finding = {
                "id": "PG004",
                "file": filepath,
                "line": 3,
                "remediation": {
                    "before": (
                        'query = "SELECT * FROM users WHERE id=" + user_id'
                    ),
                    "after": (
                        'cursor.execute('
                        '"SELECT * FROM users WHERE id=?", '
                        '(user_id,)'
                        ')'
                    )
                }
            }

            result = CodePatcher().create_patch(finding)

            self.assertEqual(result["status"], "READY")

            self.assertIn(
                '+cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))',
                result["patch"]
            )

    def test_pg003_uses_detected_variable_name(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "secrets.py")

            with open(filepath, "w") as file:
                file.write(
                    'API_KEY = "sk_live_example_key"\n'
                )

            finding = {
                "id": "PG003",
                "file": filepath,
                "line": 1,
                "code": 'API_KEY = "sk_live_example_key"',
                "remediation": {
                    "before": 'API_KEY = "secret_value"',
                    "after": (
                        'import os\n'
                        'API_KEY = os.getenv("API_KEY")'
                    )
                }
            }

            result = CodePatcher().create_patch(finding)

            self.assertEqual(result["status"], "READY")

            self.assertIn(
                '+API_KEY = os.getenv("API_KEY")',
                result["patch"]
            )

            self.assertNotIn(
                '+API_KEY = "sk_live_example_key"',
                result["patch"]
            )


if __name__ == "__main__":
    unittest.main()
