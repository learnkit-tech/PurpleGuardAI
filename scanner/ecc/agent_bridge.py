"""ECC -> PurpleGuard adapter.

ECC dispatches tasks here (the [harness_runners.purpleguard] config in
ecc2.toml invokes purpleguard_runner.py with --cwd/--task). The actual
security engines remain PurpleGuard's scanner, hacker, and remediation
system - this bridge only routes each ECC task to the existing runner
functions and returns their JSON unchanged.
"""

import sys
from pathlib import Path

PROJECT_ROOT = str(Path(__file__).resolve().parents[2])
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import purpleguard_runner


class PurpleGuardAgent:

    def __init__(self, pipeline=None):
        self.pipeline = pipeline


    def execute(self, task):
        action = task.get("action")
        project = task.get("project")


        if action == "security_scan":
            # Read-only. Use an injected pipeline when one is provided
            # (backward compatibility), otherwise call the real runner.
            if self.pipeline is not None:
                return self.pipeline.run(project)

            label = (
                task.get("task")
                or task.get("description")
                or "security scan"
            )

            return purpleguard_runner.run_scan(project, label)


        if action == "security_secure":
            # Approval gate: `approved` must be the boolean True.
            # A missing value, a string like "true", or 1 all stay
            # False, so the orchestrator runs propose-only and no
            # source file is modified without explicit approval.
            approved = task.get("approved") is True

            return purpleguard_runner.run_secure(
                project,
                approved
            )


        if action == "analyze":
            return {
                "status": "analysis_requested",
                "project": project
            }


        if action == "fix":
            return {
                "status": "fix_requested",
                "project": project
            }


        return {
            "status": "unknown_task"
        }
