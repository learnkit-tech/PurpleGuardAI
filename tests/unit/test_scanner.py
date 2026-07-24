import unittest
from scanner.engine import SecurityScanner


class TestScanner(unittest.TestCase):

    def test_detects_password(self):

        scanner = SecurityScanner(
            "tests/vulnerable_app"
        )

        results = scanner.scan()

        ids = [
            item["id"]
            for item in results
        ]

        self.assertIn(
            "PG001",
            ids
        )


    def test_detects_eval(self):

        scanner = SecurityScanner(
            "tests/vulnerable_app"
        )

        results = scanner.scan()

        ids = [
            item["id"]
            for item in results
        ]

        self.assertIn(
            "PG002",
            ids
        )def test_detects_secret(self):

    scanner = SecurityScanner(
        "tests/vulnerable_app"
    )

    results = scanner.scan()

    ids = [
        item["id"]
        for item in results
    ]

    self.assertIn(
        "PG003",
        ids
    )



if __name__ == "__main__":
    unittest.main()
