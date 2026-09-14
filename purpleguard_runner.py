#!/usr/bin/env python3

import argparse
import json
import os

from scanner.engine import SecurityScanner
from hacker.orchestrator import PurpleGuardSecurityOrchestrator


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
    orchestrator = PurpleGuardSecurityOrchestrator(
        target
    )

    return orchestrator.run(
        approved=approved
    )


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
