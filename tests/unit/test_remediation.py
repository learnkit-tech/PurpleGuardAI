import unittest

from scanner.remediation.fixes import get_fix


class TestRemediation(unittest.TestCase):

    def test_pg001_fix(self):
        fix = get_fix("PG001")

        self.assertEqual(
            fix["title"],
            "Move credentials to environment variables"
        )

        self.assertIn(
            "os.getenv",
            fix["after"]
        )


    def test_pg002_fix(self):
        fix = get_fix("PG002")

        self.assertEqual(
            fix["title"],
            "Replace unsafe eval usage"
        )

        self.assertIn(
            "literal_eval",
            fix["after"]
        )


    def test_pg004_fix(self):
        fix = get_fix("PG004")

        self.assertEqual(
            fix["title"],
            "Use parameterized SQL queries"
        )

        self.assertIn(
            "execute",
            fix["after"]
        )


if __name__ == "__main__":
    unittest.main()
