#!/usr/bin/env python3

import argparse
import json
import os
import sys

from scanner.engine import SecurityScanner
from hacker.orchestrator import PurpleGuardSecurityOrchestrator


AGENT_SURFACE_TAG = "agent_loop"

# Cmdline markers that identify the autonomous loop's own processes.
# Deliberately narrow: a human running pytest, the API server, main.py
# or any PurpleGuard CLI command matches none of these.
AGENT_LOOP_CMDLINE_MARKERS = ("run_agent", "dev_agent")

_PR_SET_CHILD_SUBREAPER = 36


def set_agent_subreaper():
    """Root every daemonized escape in this process tree.

    Called only by dev_agent/run_agent.py (the loop entry): afterwards,
    an orphan produced by setsid / double-fork inside the tree is
    reparented to the loop process instead of init, so the ancestry
    check below keeps catching it. Human surfaces never call this, so
    their daemonized children are unaffected.
    """
    try:
        import ctypes

        libc = ctypes.CDLL(None, use_errno=True)
        libc.prctl(
            _PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0
        )
        return True
    except Exception:
        return False


def _proc_cmdline(pid):
    try:
        with open("/proc/" + str(pid) + "/cmdline", "rb") as handle:
            raw = handle.read()
    except OSError:
        return ""
    if not raw:
        return ""
    return raw.replace(b"\x00", b" ").decode(
        "utf-8", "replace"
    ).strip()


def _parent_pid(pid):
    try:
        with open("/proc/" + str(pid) + "/stat", "rb") as handle:
            data = handle.read()
    except OSError:
        return None
    # comm (field 2) may contain spaces/parentheses; parse after the
    # final closing paren. Field 4 overall (index 1 here) is ppid.
    fields = data[data.rfind(b")") + 2:].split()
    try:
        return int(fields[1])
    except (IndexError, ValueError):
        return None


def _loop_rooted(cmdline):
    lowered = cmdline.lower()
    return any(
        marker in lowered
        for marker in AGENT_LOOP_CMDLINE_MARKERS
    )


def _tagged_ancestor(max_depth=64):
    """True when this process or any ancestor is the agent loop.

    /proc is kernel-owned: a shell string can rewrite the environment
    (env -u, env -i, python -E) but cannot rewrite process ancestry.
    Daemonized escapes land here too, because run_agent.py makes the
    loop a subreaper and orphans are then reparented to it.
    """
    try:
        pid = os.getpid()
        for _ in range(max_depth):
            if _loop_rooted(_proc_cmdline(pid)):
                return True
            ppid = _parent_pid(pid)
            if not ppid or ppid <= 1:
                return False
            pid = ppid
    except Exception:
        return False
    return False


def autonomous_surface():
    """True when this process belongs to the autonomous agent loop.

    Decided from kernel-owned evidence, so shell laundering cannot
    reach an approval:

    1. Process ancestry: this process, or any /proc ancestor, is the
       agent loop. ``env -u PG_EXEC_SURFACE`` and ``env -i`` do not
       touch /proc. A setsid/double-fork escape is reparented to the
       loop's subreaper (see set_agent_subreaper) and is therefore
       still an ancestor-descendant of the loop.
    2. The inherited PG_EXEC_SURFACE tag, which survives ordinary
       shell indirection and covers platforms without /proc.

    Human surfaces (terminal, API, frontend, ECC desktop dispatch)
    have neither an ancestor match nor the tag, so approval works as
    before.
    """
    if _tagged_ancestor():
        return True
    return os.environ.get("PG_EXEC_SURFACE") == AGENT_SURFACE_TAG


def refusal(approved):
    return {
        "agent": "purpleguard",
        "task": "secure",
        "status": "APPROVAL_REFUSED",
        "error": (
            "Approval refused: this process belongs to the autonomous "
            "agent surface (loop ancestry or PG_EXEC_SURFACE=" + AGENT_SURFACE_TAG + "). "
            "Source modification requires a human session: run "
            "purpleguard_runner.py --approve from a terminal, or use "
            "the approved API/frontend request."
        ),
        "approved_requested": bool(approved),
    }


def record_security_result(result, path=None):
    """Record the backend verdict of a human-approved run verbatim.

    Only called after an accepted approved=True run, so the recorded
    verdict always comes from the orchestrator's own verification -
    never derived or re-computed here. Recording failures must never
    break a remediation run, hence the broad guard.
    """
    if "verification" not in result:
        return
    try:
        from dev_agent.status import update_status

        project_root = os.path.dirname(os.path.abspath(__file__))
        status_path = path or os.path.join(
            project_root, "dev_agent", "status.json"
        )

        current = {}
        if os.path.exists(status_path):
            try:
                with open(status_path, "r") as file:
                    current = json.load(file)
            except Exception:
                current = {}

        verdict = result.get("status")
        current["security"] = {
            "stage": (
                "verified"
                if verdict == "SECURITY_VERIFIED"
                else "needs_review"
            ),
            "verdict_status": verdict,
            "confirmed_attacks": result.get("confirmed_attacks"),
            "recorded_from": "human_approved_run",
        }
        update_status(current, path=status_path)
    except Exception:
        pass


def run_scan(target, task):
    scanner = SecurityScanner(target)

    findings = scanner.scan()

    return {
        "agent": "purpleguard",
        "task": task,
        "status": "complete",
        "findings": findings,
        "count": len(findings)
    }


def run_secure(target, approved):
    # Structural approval boundary: the autonomous agent surface is
    # refused before the orchestrator is even constructed, so no code
    # path reachable from the loop can apply a patch.
    if approved and autonomous_surface():
        return refusal(approved)

    orchestrator = PurpleGuardSecurityOrchestrator(
        target
    )

    result = orchestrator.run(
        approved=approved
    )

    if approved:
        record_security_result(result)

    return result


def main():
    parser = argparse.ArgumentParser(
        description="PurpleGuardAI security and ECC harness"
    )

    parser.add_argument(
        "--cwd",
        help="Project directory"
    )

    parser.add_argument(
        "--task",
        default="security scan",
        help="Task from ECC"
    )

    parser.add_argument(
        "command",
        nargs="?",
        choices=["scan", "secure"],
        default="scan",
        help="PurpleGuard operation"
    )

    parser.add_argument(
        "--approve",
        action="store_true",
        help="Approve source modification during secure mode"
    )

    args = parser.parse_args()

    if not args.cwd:
        parser.error("--cwd is required")

    target = os.path.abspath(
        os.path.expanduser(args.cwd)
    )

    if args.command == "secure":
        if args.approve and autonomous_surface():
            print(
                json.dumps(
                    refusal(args.approve),
                    indent=2,
                    default=str
                )
            )
            sys.exit(2)
        result = run_secure(
            target,
            args.approve
        )
    else:
        result = run_scan(
            target,
            args.task
        )

    print(
        json.dumps(
            result,
            indent=2,
            default=str
        )
    )


if __name__ == "__main__":
    main()
