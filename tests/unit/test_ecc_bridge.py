import json
import os
import shlex
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


# ==========================================================================
# Phase 2 #2: structural approval boundary + coordination stage
# ==========================================================================


class AutonomousApprovalRefusalTests(unittest.TestCase):
    """A process tagged as the autonomous surface cannot approve,
    no matter what its code tries to pass."""

    TAG = {"PG_EXEC_SURFACE": "agent_loop"}

    def loop_sim(self):
        """A faithful stand-in for the autonomous loop process: same
        env tag, same subreaper and process-tree role as
        dev_agent/run_agent.py. Shell strings are executed inside this
        process tree, exactly as agent_api.tools.run_command does."""
        import subprocess

        program = (
            "import json, subprocess, sys\n"
            "sys.path.insert(0, r" + repr(str(PROJECT_ROOT)) + ")\n"
            "from purpleguard_runner import set_agent_subreaper\n"
            "set_agent_subreaper()\n"
            "print('SIM_READY', flush=True)\n"
            "for line in sys.stdin:\n"
            "    line = line.strip()\n"
            "    if not line:\n"
            "        continue\n"
            "    try:\n"
            "        cmd = json.loads(line)\n"
            "        r = subprocess.run(['sh', '-c', cmd],"
            " capture_output=True, text=True, timeout=120)\n"
            "        print(json.dumps({'rc': r.returncode,"
            " 'out': r.stdout[-2000:], 'err': r.stderr[-500:]}),"
            " flush=True)\n"
            "    except Exception as exc:\n"
            "        print(json.dumps({'rc': -1, 'out': '',"
            " 'err': str(exc)[-500:]}), flush=True)\n"
        )
        # The real loop runs as `python -m dev_agent.run_agent`, whose
        # cmdline carries the run_agent marker the ancestry check keys
        # on. The sim mirrors that by running from a marker-named file.
        import tempfile

        handle = tempfile.NamedTemporaryFile(
            prefix="run_agent_sim_",
            suffix=".py",
            delete=False,
            mode="w",
        )
        handle.write(program)
        handle.close()
        self.addCleanup(os.unlink, handle.name)

        sim = subprocess.Popen(
            [sys.executable, handle.name],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, **self.TAG},
        )
        self.addCleanup(sim.kill)
        ready = sim.stdout.readline()
        if not ready.strip():
            self.fail(
                "loop-sim failed to start: "
                + sim.stderr.read()[-500:]
            )
        return sim

    def launder(self, sim, shell_cmd):
        """Execute a shell string inside the loop-sim tree and return
        the child's result. The string may strip or wipe the inherited
        tag in any way it likes."""
        # The loop-sim reads one command per line, so a command that
        # itself contains newlines (e.g. a multi-line python -c daemon)
        # is JSON-encoded to survive the line protocol intact.
        sim.stdin.write(json.dumps(shell_cmd) + "\n")
        sim.stdin.flush()
        payload = sim.stdout.readline()
        self.assertTrue(
            payload.strip(), "loop-sim died before laundering"
        )
        return json.loads(payload)

    def runner_call(self):
        return str(PROJECT_ROOT / "purpleguard_runner.py")

    def test_shell_unset_cannot_launder_approval(self):
        """A shell string that explicitly strips the inherited tag
        (env -u) before invoking the runner must still be refused:
        approval identity is decided by kernel-owned process ancestry,
        not by a mutable variable."""
        sim = self.loop_sim()

        result = self.launder(
            sim,
            "env -u PG_EXEC_SURFACE "
            + shlex.quote(sys.executable)
            + " "
            + shlex.quote(self.runner_call())
            + " --cwd /tmp/definitely-not-a-project secure --approve",
        )

        self.assertEqual(result["rc"], 2)
        self.assertIn("APPROVAL_REFUSED", result["out"])

    def test_env_scrubbed_shell_cannot_launder_approval(self):
        """A fresh env -i shell carrying nothing but the runner call
        must still be refused: ancestry survives the environment wipe."""
        sim = self.loop_sim()

        result = self.launder(
            sim,
            "env -i "
            + shlex.quote(sys.executable)
            + " "
            + shlex.quote(self.runner_call())
            + " --cwd /tmp/definitely-not-a-project secure --approve",
        )

        self.assertEqual(result["rc"], 2)
        self.assertIn("APPROVAL_REFUSED", result["out"])

    @unittest.skipUnless(
        sys.platform.startswith("linux"),
        "daemonized-escape proof needs /proc and the Linux subreaper",
    )
    def test_daemonized_double_fork_escape_cannot_launder_approval(self):
        """The full escape pattern - double fork plus setsid so the
        runner outlives every intermediate - still lands in the loop
        tree: the loop process is a child subreaper, so the orphan is
        reparented to it and the /proc ancestry check sees the loop
        marker. The daemon exits before the runner checks ancestry, so
        this exercises real reparenting, not just live ancestors."""
        import time

        sim = self.loop_sim()

        out_path = (
            "/tmp/pg_daemon_out_"
            + str(os.getpid())
            + "_"
            + str(time.time_ns())
            + ".txt"
        )
        self.addCleanup(
            lambda: os.path.exists(out_path)
            and os.unlink(out_path)
        )

        daemon_program = (
            "import os, subprocess, sys\n"
            "if os.fork() == 0:\n"
            "    os.setsid()\n"
            "    if os.fork() == 0:\n"
            "        fh = open(" + repr(out_path) + ", 'w')\n"
            "        subprocess.Popen(\n"
            "            [sys.executable, " + repr(self.runner_call()) + ",\n"
            "             '--cwd', '/tmp/definitely-not-a-project',\n"
            "             'secure', '--approve'],\n"
            "            stdout=fh, stderr=subprocess.STDOUT)\n"
            "        os._exit(0)\n"
            "    os._exit(0)\n"
            "os.wait()\n"
        )

        shell_cmd = (
            shlex.quote(sys.executable)
            + " -c "
            + shlex.quote(daemon_program)
            + "; i=0; while [ $i -lt 100 ]; do grep -q APPROVAL_REFUSED "
            + shlex.quote(out_path)
            + " && break; i=$((i+1)); sleep 0.1; done; cat "
            + shlex.quote(out_path)
        )

        result = self.launder(sim, shell_cmd)

        self.assertIn("APPROVAL_REFUSED", result["out"])
        self.assertNotIn("Traceback", result["out"])

    def test_python_dash_c_cannot_launder_approval(self):
        """Bypassing argv entirely (python -c that imports run_secure
        and passes approved=True)        must be refused inside the loop tree:
        the ancestry check runs at call time."""
        sim = self.loop_sim()

        program = (
            "import sys; sys.path.insert(0, r"
            + repr(str(PROJECT_ROOT))
            + "); "
            "from purpleguard_runner import run_secure; "
            "print(run_secure('/tmp/definitely-not-a-project', True))"
        )
        result = self.launder(
            sim,
            shlex.quote(sys.executable) + " -c " + shlex.quote(program),
        )

        self.assertEqual(result["rc"], 0)
        self.assertIn("APPROVAL_REFUSED", result["out"])


    def test_run_secure_refuses_approval_on_tagged_surface(self):
        import purpleguard_runner as runner

        with mock.patch.dict(os.environ, self.TAG):
            with mock.patch(
                "purpleguard_runner.PurpleGuardSecurityOrchestrator"
            ) as orchestrator:
                result = runner.run_secure("/srv/app", True)

        # Refusal happens before the orchestrator is even constructed.
        orchestrator.assert_not_called()
        self.assertEqual(result["status"], "APPROVAL_REFUSED")
        self.assertTrue(result["approved_requested"])

    def test_propose_only_still_runs_on_tagged_surface(self):
        import purpleguard_runner as runner

        with mock.patch.dict(os.environ, self.TAG):
            with mock.patch(
                "purpleguard_runner.PurpleGuardSecurityOrchestrator"
            ) as orchestrator:
                orchestrator.return_value.run.return_value = {
                    "status": "APPROVAL_REQUIRED"
                }
                result = runner.run_secure("/srv/app", False)

        orchestrator.return_value.run.assert_called_once_with(
            approved=False
        )
        self.assertEqual(result["status"], "APPROVAL_REQUIRED")

    def test_human_surface_approval_unaffected(self):
        import purpleguard_runner as runner

        env = {k: v for k, v in os.environ.items()
               if k != "PG_EXEC_SURFACE"}
        with mock.patch.dict(os.environ, env, clear=True):
            with mock.patch(
                "purpleguard_runner.PurpleGuardSecurityOrchestrator"
            ) as orchestrator:
                orchestrator.return_value.run.return_value = {
                    "status": "SECURITY_VERIFIED"
                }
                result = runner.run_secure("/srv/app", True)

        orchestrator.return_value.run.assert_called_once_with(
            approved=True
        )
        self.assertEqual(result["status"], "SECURITY_VERIFIED")

    def test_cli_on_tagged_surface_refuses_with_exit_2(self):
        """Subprocess proof: the loop tags its process tree via
        dev_agent/run_agent.py; a runner invocation from that tree
        (even through a shell) must exit 2 with APPROVAL_REFUSED and
        must never run the orchestrator."""
        import subprocess

        cmd = [
            sys.executable,
            str(PROJECT_ROOT / "purpleguard_runner.py"),
            "--cwd", "/tmp/definitely-not-a-project",
            "secure", "--approve",
        ]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
            env={**os.environ, **self.TAG},
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("APPROVAL_REFUSED", result.stdout)
        # The bogus target would make any real orchestrator run fail;
        # refusal output is the only thing on stdout.
        self.assertIn("agent surface", result.stdout)

    def test_shell_inheritance_cannot_launder_approval(self):
        """The exact scenario agent_api.tools.run_command makes
        possible: the loop process shells out to invoke the runner
        with --approve. The tag is inherited through the shell, so the
        invocation is still refused."""
        import subprocess

        shell_cmd = (
            f'"{sys.executable}" '
            f'"{PROJECT_ROOT / "purpleguard_runner.py"}" '
            f'--cwd /tmp/definitely-not-a-project secure --approve'
        )
        result = subprocess.run(
            ["sh", "-c", shell_cmd],
            capture_output=True,
            text=True,
            timeout=60,
            env={**os.environ, **self.TAG},
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("APPROVAL_REFUSED", result.stdout)


class VerdictRecordingTests(unittest.TestCase):
    """The verdict is recorded only from a human-approved run and is
    copied verbatim from backend evidence, never derived."""

    def test_propose_only_run_records_nothing(self):
        import purpleguard_runner as runner

        env = {k: v for k, v in os.environ.items()
               if k != "PG_EXEC_SURFACE"}
        with mock.patch.dict(os.environ, env, clear=True):
            with mock.patch(
                "purpleguard_runner.PurpleGuardSecurityOrchestrator"
            ) as orchestrator:
                orchestrator.return_value.run.return_value = {
                    "status": "APPROVAL_REQUIRED"
                }
                with mock.patch(
                    "dev_agent.status.update_status"
                ) as update_status:
                    runner.run_secure("/srv/app", False)

        update_status.assert_not_called()

    def test_approved_run_records_backend_verdict_verbatim(self):
        import purpleguard_runner as runner

        env = {k: v for k, v in os.environ.items()
               if k != "PG_EXEC_SURFACE"}
        with mock.patch.dict(os.environ, env, clear=True):
            with mock.patch(
                "purpleguard_runner.PurpleGuardSecurityOrchestrator"
            ) as orchestrator:
                orchestrator.return_value.run.return_value = {
                    "status": "SECURITY_VERIFIED",
                    "confirmed_attacks": 8,
                    "verification": {"verdict": {"status": "SECURITY_VERIFIED"}},
                }
                with mock.patch(
                    "dev_agent.status.update_status"
                ) as update_status:
                    runner.run_secure("/srv/app", True)

        update_status.assert_called_once()
        recorded = update_status.call_args[0][0]
        self.assertEqual(
            recorded["security"]["verdict_status"], "SECURITY_VERIFIED"
        )
        self.assertEqual(recorded["security"]["stage"], "verified")
        self.assertEqual(
            recorded["security"]["recorded_from"], "human_approved_run"
        )

    def test_non_verified_verdict_records_needs_review(self):
        import purpleguard_runner as runner

        with mock.patch(
            "dev_agent.status.update_status"
        ) as update_status:
            runner.record_security_result(
                {
                    "status": "SECURITY_NOT_VERIFIED",
                    "confirmed_attacks": 3,
                    "verification": {"verdict": {"status": "SECURITY_NOT_VERIFIED"}},
                },
                path="/tmp/unused.json",
            )

        recorded = update_status.call_args[0][0]
        self.assertEqual(recorded["security"]["stage"], "needs_review")

    def test_run_without_verification_records_nothing(self):
        import purpleguard_runner as runner

        with mock.patch(
            "dev_agent.status.update_status"
        ) as update_status:
            runner.record_security_result(
                {"status": "APPROVAL_REQUIRED"},
                path="/tmp/unused.json",
            )

        update_status.assert_not_called()


class SecurityCoordinationStageTests(unittest.TestCase):
    """The loop's propose-only coordination stage."""

    TASK_TEXT = "Run the PurpleGuard security pipeline"

    def test_task_routes_to_security(self):
        self.assertEqual(route_task(self.TASK_TEXT)["area"], "security")

    def test_stage_dispatches_propose_only_and_persists_state(self):
        from dev_agent.security_coordination import (
            run_security_coordination,
        )

        captured = {}

        class FakeBridge:
            def execute(self, task):
                captured["task"] = task
                return {
                    "status": "APPROVAL_REQUIRED",
                    "confirmed_attacks": 8,
                }

        with mock.patch(
            "scanner.ecc.agent_bridge.PurpleGuardAgent",
            return_value=FakeBridge(),
        ):
            with mock.patch(
                "dev_agent.security_coordination.get_status",
                return_value={"status": "building"},
            ):
                with mock.patch(
                    "dev_agent.security_coordination.update_status"
                ) as update_status:
                    result = run_security_coordination(
                        {"task": self.TASK_TEXT, "project": "/srv/app"},
                        route_task(self.TASK_TEXT),
                        status_path="/tmp/unused.json",
                    )

        # Propose-only dispatch: no approval flag whatsoever.
        self.assertEqual(captured["task"]["action"], "security_secure")
        self.assertNotIn("approved", captured["task"])
        self.assertEqual(result["status"], "APPROVAL_REQUIRED")

        recorded = update_status.call_args[0][0]
        coordination = recorded["security_coordination"]
        self.assertEqual(coordination["stage"], "awaiting_approval")
        self.assertEqual(
            coordination["backend_status"], "APPROVAL_REQUIRED"
        )
        self.assertIn("cannot approve", coordination["next_step"])

    def test_end_to_end_loop_coordination_is_propose_only(self):
        """Real bridge, real vulnerable fixture copy: the stage ends
        at APPROVAL_REQUIRED, the recorded stage is awaiting_approval,
        and the source is byte-identical."""
        import subprocess
        from dev_agent.security_coordination import (
            run_security_coordination,
        )

        fixture = PROJECT_ROOT / "tests" / "hacker_target"
        status_file = tempfile.NamedTemporaryFile(
            suffix=".json", delete=False
        )
        status_file.close()
        self.addCleanup(os.unlink, status_file.name)

        with tempfile.TemporaryDirectory() as project:
            shutil.copytree(fixture, project, dirs_exist_ok=True)
            subprocess.run(
                [sys.executable, os.path.join(project, "reset_vulnerable.py")],
                capture_output=True,
                timeout=30,
            )
            source = Path(project) / "app.py"
            before = source.read_bytes()

            # The loop process tree always carries the tag.
            with mock.patch.dict(os.environ, {"PG_EXEC_SURFACE": "agent_loop"}):
                with mock.patch(
                    "dev_agent.status.STATUS_FILE", status_file.name
                ):
                    result = run_security_coordination(
                        {"task": self.TASK_TEXT, "project": project},
                        route_task(self.TASK_TEXT),
                        status_path=status_file.name,
                    )

            self.assertEqual(result["status"], "APPROVAL_REQUIRED")
            self.assertEqual(source.read_bytes(), before)

            with open(status_file.name) as file:
                recorded = json.load(file)
        self.assertEqual(
            recorded["security_coordination"]["stage"],
            "awaiting_approval",
        )

    def test_run_agent_entrypoint_tags_the_process_tree(self):
        """The structural boundary exists because the loop entrypoint
        sets the tag before anything else imports; verify the file
        does so unconditionally at module import time."""
        source = (
            PROJECT_ROOT / "dev_agent" / "run_agent.py"
        ).read_text()
        self.assertIn(
            'os.environ["PG_EXEC_SURFACE"] = "agent_loop"',
            source,
        )
        # The tag must be set before the loop import chain.
        self.assertLess(
            source.index('os.environ["PG_EXEC_SURFACE"]'),
            source.index("from dev_agent.loop"),
        )

    def test_api_process_stays_untagged(self):
        """The API serves frontend approvals via /secure; importing
        the API module must therefore never set the autonomous tag in
        its own process (the loop runs in a subprocess instead), and
        the API must never import the tagging entrypoint."""
        from api import server as api_server

        self.assertNotEqual(
            os.environ.get("PG_EXEC_SURFACE"), "agent_loop"
        )

        source_lines = open(api_server.__file__).read().splitlines()
        import_lines = [
            line for line in source_lines
            if line.strip().startswith(("from ", "import "))
        ]
        self.assertFalse(
            any("dev_agent.run_agent" in line for line in import_lines),
            msg="api/server.py must not import the tagging entrypoint",
        )


class WorkerCompletionTests(unittest.TestCase):

    def test_awaiting_approval_task_stays_open(self):
        from dev_agent.status import security_completion_status

        status = {
            "security_coordination": {
                "task": self.TASK_TEXT,
                "stage": "awaiting_approval",
            }
        }
        self.assertEqual(
            security_completion_status(self.TASK_TEXT, status),
            "awaiting_approval",
        )

    TASK_TEXT = "Run the PurpleGuard security pipeline"

    def test_other_tasks_complete_normally(self):
        from dev_agent.status import security_completion_status

        self.assertEqual(
            security_completion_status("build the dashboard", {}),
            "completed",
        )
        self.assertEqual(
            security_completion_status(
                self.TASK_TEXT,
                {"security_coordination": {
                    "task": "a different task",
                    "stage": "awaiting_approval",
                }},
            ),
            "completed",
        )


if __name__ == "__main__":
    unittest.main()
