import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scanner.ecc.agent_bridge import PurpleGuardAgent
from dev_agent.task_router import route_task


VULNERABLE_SOURCE = (
    "import os\n"
    "\n"
    "def run(host):\n"
    "    os.system(\"ping \" + host)\n"
)


class EccBridgeScanTests(unittest.TestCase):
    """ECC dispatches -> bridge -> real PurpleGuard runner."""

    def make_project(self):
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        source = Path(temp_dir.name) / "vulnerable_app.py"
        source.write_text(VULNERABLE_SOURCE)
        return temp_dir.name, source

    def test_security_scan_dispatches_to_real_runner(self):
        project, _ = self.make_project()

        result = PurpleGuardAgent().execute({
            "action": "security_scan",
            "project": project
        })

        self.assertEqual(result["agent"], "purpleguard")
        self.assertEqual(result["status"], "complete")
        self.assertGreaterEqual(result["count"], 1)
        ids = [item["id"] for item in result["findings"]]
        self.assertIn("PG005", ids)

    def test_security_scan_returns_runner_json_shape(self):
        project, _ = self.make_project()

        result = PurpleGuardAgent().execute({
            "action": "security_scan",
            "project": project
        })

        self.assertEqual(
            set(result.keys()),
            {"agent", "task", "status", "findings", "count"}
        )
        self.assertEqual(result["count"], len(result["findings"]))

    def test_injected_pipeline_still_used_when_provided(self):
        pipeline = mock.Mock()
        pipeline.run.return_value = {"status": "injected"}

        result = PurpleGuardAgent(pipeline).execute({
            "action": "security_scan",
            "project": "/anywhere"
        })

        pipeline.run.assert_called_once_with("/anywhere")
        self.assertEqual(result, {"status": "injected"})

    def test_unknown_action_reported(self):
        result = PurpleGuardAgent().execute({
            "action": "deploy",
            "project": "/anywhere"
        })
        self.assertEqual(result, {"status": "unknown_task"})


class EccBridgeApprovalGateTests(unittest.TestCase):
    """approved=True only when literally boolean True."""

    def test_missing_approval_stays_false(self):
        with mock.patch("purpleguard_runner.run_secure") as run_secure:
            PurpleGuardAgent().execute({
                "action": "security_secure",
                "project": "/srv/app"
            })
        run_secure.assert_called_once_with("/srv/app", False)

    def test_truthy_non_boolean_values_stay_false(self):
        for value in ["true", "True", 1, "yes"]:
            with mock.patch("purpleguard_runner.run_secure") as run_secure:
                PurpleGuardAgent().execute({
                    "action": "security_secure",
                    "project": "/srv/app",
                    "approved": value
                })
            args, kwargs = run_secure.call_args
            self.assertEqual(
                (args, kwargs),
                (("/srv/app", False), {}),
                msg=f"approved={value!r} must not approve"
            )

    def test_explicit_boolean_true_approves(self):
        with mock.patch("purpleguard_runner.run_secure") as run_secure:
            PurpleGuardAgent().execute({
                "action": "security_secure",
                "project": "/srv/app",
                "approved": True
            })
        run_secure.assert_called_once_with("/srv/app", True)


class EccBridgeSecureProposeOnlyTests(unittest.TestCase):
    """A real propose-only secure run must not modify source."""

    def test_secure_without_approval_leaves_source_untouched(self):
        fixture = PROJECT_ROOT / "tests" / "hacker_target"

        with tempfile.TemporaryDirectory() as project:
            shutil.copytree(fixture, project, dirs_exist_ok=True)

            # Put the copy into its intentionally vulnerable state so
            # there is something real to propose a fix for.
            import subprocess
            subprocess.run(
                [sys.executable, os.path.join(project, "reset_vulnerable.py")],
                capture_output=True,
                timeout=30,
            )

            source = Path(project) / "app.py"
            before = source.read_bytes()

            result = PurpleGuardAgent().execute({
                "action": "security_secure",
                "project": project
            })

            self.assertIsInstance(result, dict)
            self.assertEqual(
                source.read_bytes(), before,
                msg="propose-only secure run must not modify source"
            )
            self.assertGreater(result.get("confirmed_attacks") or 0, 0)
            self.assertEqual(result.get("status"), "APPROVAL_REQUIRED")
            remediation = result.get("remediation") or {}
            self.assertFalse(remediation.get("approved", False))


class TaskRouterSecurityRouteTests(unittest.TestCase):

    def test_security_task_routes_to_security_area(self):
        route = route_task("run the security scan pipeline")
        self.assertEqual(route["area"], "security")
        self.assertIn("purpleguard_runner.py", route["files"])

    def test_secure_task_routes_to_security_area(self):
        self.assertEqual(route_task("secure this app")["area"], "security")

    def test_existing_routes_unchanged(self):
        self.assertEqual(route_task("build the dashboard")["area"], "dashboard")
        self.assertEqual(route_task("add an api endpoint")["area"], "api")
        self.assertEqual(
            route_task("fix vulnerability rules")["area"], "scanner"
        )
        self.assertEqual(route_task("export sarif report")["area"], "reporting")
        self.assertEqual(route_task("refactor everything")["area"], "general")


class AgentStatusEndpointTests(unittest.TestCase):

    def test_agent_status_is_available(self):
        from api.server import app

        client = app.test_client()
        response = client.get("/agent/status")

        self.assertEqual(response.status_code, 200)
        self.assertIn("status", response.get_json())


if __name__ == "__main__":
    unittest.main()
