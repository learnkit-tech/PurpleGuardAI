import unittest
from scanner.engine import SecurityScanner


class TestScanner(unittest.TestCase):

    def test_detects_password(self):

        scanner = SecurityScanner(
            "tests/vulnerable_app"
        )

        results = scanner.scan()

        issues = [
            item["issue"]
            for item in results
        ]

        self.assertIn(
            "Possible hardcoded password",
            issues
        )


    def test_detects_eval(self):

        scanner = SecurityScanner(
            "tests/vulnerable_app"
        )

        results = scanner.scan()

        issues = [
            item["issue"]
            for item in results
        ]

        self.assertIn(
            "Dangerous eval() usage",
            issues
        )


if __name__ == "__main__":
    unittest.main()
