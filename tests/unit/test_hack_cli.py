import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]

MAIN_PY = PROJECT_ROOT / "main.py"

WEB_FIXTURE = PROJECT_ROOT / "tests" / "hacker_target_web"


def file_hash(path):
    with open(path, "rb") as file:
        return hashlib.sha256(file.read()).hexdigest()


def run_hack(args, cwd):
    return subprocess.run(
        [sys.executable, str(MAIN_PY), "hack"] + args,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=300,
    )


class TestHackCli(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls._temp = tempfile.TemporaryDirectory()

    @classmethod
    def tearDownClass(cls):
        cls._temp.cleanup()

    def _make_vulnerable_copy(self):
        """Copy the web fixture and restore its vulnerable state."""

        project = Path(self._temp.name) / self.id().rsplit(".", 1)[-1]

        shutil.copytree(WEB_FIXTURE, project)

        subprocess.run(
            [sys.executable, "reset_vulnerable.py"],
            cwd=project,
            capture_output=True,
            text=True,
            timeout=60,
        )

        return project

    def test_hack_requires_approval_and_modifies_nothing(self):
        """Without --approve nothing may be modified."""

        project = self._make_vulnerable_copy()

        app_py = project / "web_app.py"

        before = file_hash(app_py)

        # The fixture ships with a tracked .bak; only NEW backups
        # would indicate an unauthorized modification.
        baks_before = set(
            project.rglob("*.purpleguard.bak")
        )

        result = run_hack([str(project)], cwd=self._temp.name)

        self.assertEqual(
            result.returncode,
            0,
            msg=f"{result.stdout}\n{result.stderr}",
        )

        self.assertIn(
            "APPROVAL_REQUIRED",
            result.stdout,
        )

        self.assertIn(
            "[CONFIRMED]",
            result.stdout,
        )

        self.assertIn(
            "No files were modified",
            result.stdout,
        )

        self.assertEqual(
            file_hash(app_py),
            before,
        )

        self.assertEqual(
            set(project.rglob("*.purpleguard.bak")),
            baks_before,
        )

    def test_hack_approve_runs_full_pipeline(self):
        """
        With --approve the pipeline must remediate the confirmed
        auto-fixable findings, keep manual-review findings
        unpatched, and report the verification layers honestly.
        """

        project = self._make_vulnerable_copy()

        result = run_hack(
            [str(project), "--approve"],
            cwd=project,
        )

        self.assertEqual(
            result.returncode,
            0,
            msg=f"{result.stdout}\n{result.stderr}",
        )

        # Report written relative to cwd (the temp project).
        report_path = project / "reports" / "orchestrator_report.json"

        self.assertTrue(report_path.exists())

        with open(report_path) as file:
            report = json.load(file)

        self.assertEqual(
            report["status"],
            "SECURITY_VERIFIED",
        )

        remediation_results = report["remediation"]["result"]["results"]

        self.assertTrue(remediation_results)

        for item in remediation_results:
            self.assertEqual(
                item["status"],
                "APPLIED",
                msg=str(item.get("findings")),
            )

        fixed_ids = [
            finding_id
            for item in remediation_results
            for finding_id in item["findings"]
        ]

        self.assertIn("PG005", fixed_ids)
        self.assertIn("PG007", fixed_ids)
        self.assertIn("PG008", fixed_ids)
        self.assertIn("PG009", fixed_ids)
        self.assertIn("PG010", fixed_ids)

        # The remediated source must no longer shell out, eval,
        # deserialise pickle, or make unvalidated outbound
        # requests.
        app_source = (project / "web_app.py").read_text()

        self.assertNotIn("shell=True", app_source)
        self.assertNotIn("os.popen", app_source)
        self.assertNotIn("pickle.loads", app_source)
        self.assertIn("ALLOWED_PREFIX", app_source)
        self.assertIn("json.loads", app_source)

        # A reversible backup must exist for the patched file.
        self.assertTrue(
            (project / "web_app.py.purpleguard.bak").exists()
        )

        # All 8 re-attacks must be blocked.
        hacker = report["verification"]["hacker"]
        self.assertTrue(hacker.get("all_attacks_blocked"))

        # The verdict block must be printed.
        self.assertIn("FINAL VERDICT:", result.stdout)
        self.assertIn("SECURITY_VERIFIED", result.stdout)

    def test_hack_on_guarded_target_confirms_nothing(self):
        """
        A remediated target must produce NO_CONFIRMED_ATTACKS and
        remain byte-identical.
        """

        project = Path(self._temp.name) / "guarded"

        shutil.copytree(WEB_FIXTURE, project)

        app_py = project / "web_app.py"

        before = file_hash(app_py)

        result = run_hack([str(project)], cwd=self._temp.name)

        self.assertEqual(
            result.returncode,
            0,
            msg=f"{result.stdout}\n{result.stderr}",
        )

        self.assertIn(
            "NO_CONFIRMED_ATTACKS",
            result.stdout,
        )

        self.assertEqual(
            file_hash(app_py),
            before,
        )


if __name__ == "__main__":
    unittest.main()
