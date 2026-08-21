import unittest

from scanner.remediation.diff import generate_diff


class TestPatchGenerator(unittest.TestCase):

    def test_patch_creation(self):

        patch = generate_diff(
            'password = "admin123"',
            'password = os.getenv("APP_PASSWORD")'
        )

        self.assertIn(
            "-password = \"admin123\"",
            patch
        )

        self.assertIn(
            "+password = os.getenv(\"APP_PASSWORD\")",
            patch
        )


if __name__ == "__main__":
    unittest.main()
