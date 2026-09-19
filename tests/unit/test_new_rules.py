import os
import tempfile
import unittest

from scanner.engine import SecurityScanner


class TestNewRules(unittest.TestCase):

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

    # ---------------------------------------------------------
    # PG005: command injection
    # ---------------------------------------------------------

    def test_detects_os_system(self):

        results = self.scan_code(
            "command.py",
            'import os\n'
            'os.system("ping " + host)\n'
        )

        self.assertIn("PG005", self.ids(results))

    def test_detects_os_popen(self):

        results = self.scan_code(
            "command.py",
            'import os\n'
            'stream = os.popen("ping " + host)\n'
        )

        self.assertIn("PG005", self.ids(results))

    def test_detects_subprocess_shell_true(self):

        results = self.scan_code(
            "command.py",
            'import subprocess\n'
            'subprocess.run(cmd, shell=True)\n'
        )

        self.assertIn("PG005", self.ids(results))

    def test_allows_subprocess_list_form(self):
        """
        The remediated pattern produced by the patcher
        (list argument + shell=False) must pass the static
        rescan so verification can succeed.
        """

        results = self.scan_code(
            "command.py",
            'import subprocess\n'
            'subprocess.run([cmd], shell=False)\n'
        )

        self.assertNotIn("PG005", self.ids(results))

    def test_allows_plain_subprocess_run(self):

        results = self.scan_code(
            "command.py",
            'import subprocess\n'
            'subprocess.run(["ping", host])\n'
        )

        self.assertNotIn("PG005", self.ids(results))

    def test_does_not_flag_similarly_named_owners(self):
        """
        A method called .system() or .run() on an arbitrary
        object is not an os/subprocess call.
        """

        results = self.scan_code(
            "command.py",
            'scheduler.run(task)\n'
            'universe.system(star)\n'
        )

        self.assertNotIn("PG005", self.ids(results))

    # ---------------------------------------------------------
    # PG007: reflected XSS
    # ---------------------------------------------------------

    def test_detects_unescaped_response(self):

        results = self.scan_code(
            "xss.py",
            'from flask import Response\n'
            'name = request.args.get("name")\n'
            'Response("Hello " + name)\n'
        )

        self.assertIn("PG007", self.ids(results))

    def test_detects_make_response(self):

        results = self.scan_code(
            "xss.py",
            'name = request.form["name"]\n'
            'make_response("<b>" + name + "</b>")\n'
        )

        self.assertIn("PG007", self.ids(results))

    def test_allows_escaped_response(self):
        """
        A variable guarded by markupsafe.escape() with a
        raise/return on failure must not be flagged.
        """

        results = self.scan_code(
            "xss.py",
            'from markupsafe import escape\n'
            'name = request.args.get("name")\n'
            'if not escape(name):\n'
            '    return "bad input"\n'
            'Response("Hello " + name)\n'
        )

        self.assertNotIn("PG007", self.ids(results))

    def test_allows_literal_response(self):

        results = self.scan_code(
            "xss.py",
            'Response("Hello world")\n'
        )

        self.assertNotIn("PG007", self.ids(results))

    # ---------------------------------------------------------
    # PG008: open redirect
    # ---------------------------------------------------------

    def test_detects_unvalidated_redirect(self):

        results = self.scan_code(
            "redirect.py",
            'from flask import redirect\n'
            'next_url = request.args.get("next")\n'
            'redirect(next_url)\n'
        )

        self.assertIn("PG008", self.ids(results))

    def test_allows_relative_only_redirect(self):
        """
        A destination guarded by a startswith("/") check with a
        raise/return on failure must not be flagged.
        """

        results = self.scan_code(
            "redirect.py",
            'from flask import redirect\n'
            'next_url = request.args.get("next")\n'
            "if not next_url.startswith('/'):\n"
            '    raise ValueError("blocked")\n'
            'redirect(next_url)\n'
        )

        self.assertNotIn("PG008", self.ids(results))

    def test_allows_literal_redirect(self):

        results = self.scan_code(
            "redirect.py",
            'redirect("/dashboard")\n'
        )

        self.assertNotIn("PG008", self.ids(results))


if __name__ == "__main__":
    unittest.main()
