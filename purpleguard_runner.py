#!/usr/bin/env python3

import argparse
import json
import os
import sys

from scanner.engine import SecurityScanner


def main():
    parser = argparse.ArgumentParser(
        description="PurpleGuardAI ECC harness"
    )

    parser.add_argument(
        "--cwd",
        required=True,
        help="Project directory to scan"
    )

    parser.add_argument(
        "--task",
        default="security scan",
        help="Task from ECC"
    )

    args = parser.parse_args()

    target = os.path.abspath(args.cwd)

    scanner = SecurityScanner(target)

    findings = scanner.scan()

    result = {
        "agent": "purpleguard",
        "task": args.task,
        "status": "complete",
        "findings": findings,
        "count": len(findings)
    }

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
