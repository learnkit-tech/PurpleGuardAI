import os
import subprocess
import sys
import unittest


PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)


def run_repo_command(args, timeout=120):
    return subprocess.run(
        [sys.executable] + args,
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


class TestPackagingSanityCheck(unittest.TestCase):

    def test_check_packaging_script_passes(self):
        """scripts/check_packaging.py must exit 0 and finish with PACKAGING OK."""

        result = run_repo_command(
            ["scripts/check_packaging.py"]
        )

        self.assertEqual(
            result.returncode,
            0,
            msg=(
                "check_packaging failed:\n"
                f"{result.stdout}\n{result.stderr}"
            ),
        )

        self.assertIn(
            "PACKAGING OK",
            result.stdout,
        )

    def test_check_packaging_reports_skip_on_old_toolchain(self):
        """
        On toolchains older than setuptools 77 the metadata build
        layer must be skipped with a notice, never a failure.
        """

        result = run_repo_command(
            ["scripts/check_packaging.py"]
        )

        if "SKIP" in result.stdout:
            self.assertIn(
                "structural checks still ran",
                result.stdout,
            )

    def test_pyproject_declares_console_script(self):
        """pyproject.toml must expose the purpleguard entry point."""

        result = run_repo_command(
            ["-c", "import tomllib"]
        )

        if result.returncode != 0:
            self.skipTest(
                "Python < 3.11 without tomllib"
            )

        probe = (
            "import tomllib\n"
            "with open('pyproject.toml', 'rb') as f:\n"
            "    data = tomllib.load(f)\n"
            "scripts = data['project']['scripts']\n"
            "assert 'purpleguard' in scripts, scripts\n"
            "assert scripts['purpleguard'] == "
            "'purpleguard_cli:main', scripts\n"
            "print('OK')\n"
        )

        result = run_repo_command(["-c", probe])

        self.assertEqual(
            result.returncode,
            0,
            msg=result.stderr,
        )

    def test_pyproject_name_matches_repository(self):
        """The distribution name must be purpleguard-ai."""

        probe = (
            "import tomllib\n"
            "with open('pyproject.toml', 'rb') as f:\n"
            "    data = tomllib.load(f)\n"
            "assert data['project']['name'] == "
            "'purpleguard-ai', data['project']['name']\n"
            "print('OK')\n"
        )

        result = run_repo_command(["-c", probe])

        if result.returncode != 0 and "ModuleNotFoundError" in (
            result.stderr
        ):
            self.skipTest(
                "Python < 3.11 without tomllib"
            )

        self.assertEqual(
            result.returncode,
            0,
            msg=result.stderr,
        )


AUTO_FIXABLE_SOURCE = (
    'def calculate(expression):\n'
    '    return eval(expression)\n'
)

MANUAL_REVIEW_SOURCE = (
    'import urllib.request\n'
    '\n'
    'def fetch(request):\n'
    '    url = request.args.get("url")\n'
    '    return urllib.request.urlopen(url, timeout=2)\n'
)


class TestReviewQueue(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        import tempfile

        cls._tempdir = tempfile.TemporaryDirectory()
        cls.target = cls._tempdir.name

        with open(
            os.path.join(cls.target, "calc.py"),
            "w",
        ) as file:
            file.write(AUTO_FIXABLE_SOURCE)

        with open(
            os.path.join(cls.target, "fetcher.py"),
            "w",
        ) as file:
            file.write(MANUAL_REVIEW_SOURCE)

    @classmethod
    def tearDownClass(cls):
        cls._tempdir.cleanup()

    def test_review_splits_auto_fixable_and_manual(self):
        """
        The review queue must separate provably auto-fixable
        findings from those requiring manual review.
        """

        from scanner.remediation.patcher import CodePatcher
        from scanner.developer.session import DeveloperSession

        session = DeveloperSession(self.target)

        findings = session.scan().get(
            "findings",
            []
        )

        self.assertTrue(findings)

        patcher = CodePatcher()

        auto_fixable = [
            finding
            for finding in findings
            if patcher.can_auto_fix(finding)
        ]

        requires_review = [
            finding
            for finding in findings
            if not patcher.can_auto_fix(finding)
        ]

        self.assertEqual(
            len(auto_fixable) + len(requires_review),
            len(findings),
        )

        self.assertIn(
            "PG002",
            [finding["id"] for finding in auto_fixable],
        )

        # PG009 (SSRF) must never be auto-fixable.
        self.assertIn(
            "PG009",
            [finding["id"] for finding in requires_review],
        )

    def test_review_subprocess_lists_findings(self):
        """`python main.py review <target>` must exit 0 and list findings."""

        result = run_repo_command(
            ["main.py", "review", self.target]
        )

        self.assertEqual(
            result.returncode,
            0,
            msg=f"{result.stdout}\n{result.stderr}",
        )

        self.assertIn(
            "Review Queue",
            result.stdout,
        )

        self.assertIn(
            "finding(s)",
            result.stdout,
        )

        # The auto-fixable bucket names the approval command.
        self.assertIn(
            "--approve",
            result.stdout,
        )

        self.assertIn(
            "PG002",
            result.stdout,
        )

        self.assertIn(
            "Requires manual review",
            result.stdout,
        )

        self.assertIn(
            "PG009",
            result.stdout,
        )

    def test_review_subprocess_clean_project(self):
        """A clean project must produce the all-clear message."""

        import tempfile

        with tempfile.TemporaryDirectory() as clean:

            with open(
                os.path.join(clean, "app.py"),
                "w",
            ) as file:
                file.write("value = 41\n")

            result = run_repo_command(
                ["main.py", "review", clean]
            )

        self.assertEqual(
            result.returncode,
            0,
            msg=f"{result.stdout}\n{result.stderr}",
        )

        self.assertIn(
            "No vulnerabilities detected",
            result.stdout,
        )


if __name__ == "__main__":
    unittest.main()
