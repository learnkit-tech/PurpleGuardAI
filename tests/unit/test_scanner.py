import os
import tempfile
import unittest

from scanner.engine import SecurityScanner


class TestScanner(unittest.TestCase):

    def scan_code(self, filename, code):
        with tempfile.TemporaryDirectory() as project:

            filepath = os.path.join(project, filename)

            with open(filepath, "w") as file:
                file.write(code)

            scanner = SecurityScanner(project)

            return scanner.scan()

    def test_detects_password(self):

        results = self.scan_code(
            "password.py",
            'password = "admin123"\n'
        )

        ids = [
            item["id"]
            for item in results
        ]

        self.assertIn("PG001", ids)

    def test_detects_secure_password(self):

        results = self.scan_code(
            "secure_password.py",
            'import os\n'
            'password = os.getenv("APP_PASSWORD")\n'
        )

        ids = [
            item["id"]
            for item in results
        ]

        self.assertNotIn("PG001", ids)

    def test_detects_eval(self):

        results = self.scan_code(
            "dangerous.py",
            'eval(user_input)\n'
        )

        ids = [
            item["id"]
            for item in results
        ]

        self.assertIn("PG002", ids)

    def test_detects_secret(self):

        results = self.scan_code(
            "secret.py",
            'API_KEY = "sk_live_example_key"\n'
        )

        ids = [
            item["id"]
            for item in results
        ]

        self.assertIn("PG003", ids)

    def test_detects_sql_injection(self):

        results = self.scan_code(
            "sql.py",
            'user_id = input("ID: ")\n'
            'query = "SELECT * FROM users WHERE id=" + user_id\n'
        )

        ids = [
            item["id"]
            for item in results
        ]

        self.assertIn("PG004", ids)
          
    def test_detects_command_injection(self):

        results = self.scan_code(
            "command.py",
            'import os\n'
            'user_input = input("Command: ")\n'
            'os.system(user_input)\n'
        )

        ids = [
            item["id"]
            for item in results
        ]

        self.assertIn("PG005", ids)

    def test_detects_subprocess_shell(self):

        results = self.scan_code(
            "command.py",
            'import subprocess\n'
            'subprocess.run(user_input, shell=True)\n'
        )

        ids = [
            item["id"]
            for item in results
        ]

        self.assertIn("PG005", ids)

if __name__ == "__main__":
    unittest.main()
      
