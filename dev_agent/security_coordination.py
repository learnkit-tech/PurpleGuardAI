"""ECC/PurpleGuard security coordination stage.

Called by the autonomous loop for security pipeline tasks. Propose-only
by construction: it dispatches security_secure without an approval
flag, so the bridge gate keeps it at APPROVAL_REQUIRED, and it records
"awaiting_approval" for a human. The verdict itself is recorded by
purpleguard_runner.record_security_result during the human-approved
run - never here, so the loop cannot write "verified".

Kept free of agent_api/LLM imports on purpose: the loop module chain
needs optional dependencies, this module must always be importable and
testable.
"""

from dev_agent.status import get_status, update_status


def run_security_coordination(task, route, status_path=None):

    from scanner.ecc.agent_bridge import PurpleGuardAgent

    project = (
        task.get("project")
        or route.get("project")
        or "."
    )

    result = PurpleGuardAgent().execute(
        {
            "action": "security_secure",
            "project": project,
        }
    )

    status = get_status()
    status["security_coordination"] = {
        "task": task.get("task"),
        "project": project,
        "stage": "awaiting_approval",
        "backend_status": result.get("status"),
        "confirmed_attacks": result.get("confirmed_attacks"),
        "next_step": (
            "Human approval required: run "
            "purpleguard_runner.py --approve from a terminal, "
            "or approve from the PurpleGuard frontend. The "
            "autonomous loop cannot approve."
        ),
    }
    update_status(status, path=status_path)

    return result
