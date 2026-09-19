#!/usr/bin/env python3

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from hacker.engine import PurpleGuardHacker
from hacker.planner import AttackPlanner
from hacker.validation.local_target import LocalTarget
from hacker.validation.validator import LocalAttackValidator


def main():

    if len(sys.argv) != 2:
        print(
            "Usage: python scripts/hack.py "
            "<authorized-local-target>"
        )
        sys.exit(1)

    target_path = Path(sys.argv[1]).resolve()

    if not target_path.is_dir():
        print(f"Target does not exist: {target_path}")
        sys.exit(1)

    print("=" * 70)
    print("PURPLEGUARD HACKER")
    print("=" * 70)

    print(f"[TARGET] {target_path}")
    print("[MODE] AUTHORIZED LOCAL VALIDATION")
    print()

    # ---------------------------------------------------------
    # 1. RECON
    # ---------------------------------------------------------

    print("[1/5] Reconnaissance...")

    hacker = PurpleGuardHacker(
        str(target_path)
    )

    recon = hacker.summary()

    print(
        f"      Files analyzed: "
        f"{recon['files_analyzed']}"
    )

    print(
        f"      Attack surfaces: "
        f"{len(recon['attack_surfaces'])}"
    )

    print(
        f"      Attack paths: "
        f"{len(recon['attack_paths'])}"
    )

    # ---------------------------------------------------------
    # 2. PLAN
    # ---------------------------------------------------------

    print()
    print("[2/5] Planning attacks...")

    planner = AttackPlanner()

    plans = planner.plan(
        recon["attack_paths"]
    )

    for plan in plans:
        print(
            f"      {plan.path_id} | "
            f"{plan.category} | "
            f"{plan.severity} | "
            f"{plan.validator}"
        )

    if not plans:

        print("      No supported attack paths found.")

        output = {
            "target": str(target_path),
            "recon": recon,
            "plans": [],
            "validation": [],
            "confirmed_attacks": 0,
        }

        output_path = Path(
            "reports/hacker_report.json"
        )

        output_path.parent.mkdir(
            exist_ok=True
        )

        with open(
            output_path,
            "w",
            encoding="utf-8",
        ) as file:

            json.dump(
                output,
                file,
                indent=4,
            )

        print()
        print(f"REPORT: {output_path}")

        return

    # ---------------------------------------------------------
    # 3. START TARGET
    # ---------------------------------------------------------

    print()
    print("[3/5] Starting authorized target...")

    target = LocalTarget(
        str(target_path)
    )

    try:

        started = target.start()

        print(
            f"      Target running at "
            f"{target.base_url}"
        )

        validator = LocalAttackValidator(
            target.base_url
        )

        # -----------------------------------------------------
        # 4. EXECUTE PLANNED VALIDATIONS
        # -----------------------------------------------------

        print()
        print("[4/5] Executing planned validations...")

        validation_results = []
        confirmed = []

        validator_methods = {
            "validate_sql_behavior":
                validator.validate_sql_behavior,

            "validate_calculator":
                validator.validate_calculator,

            "validate_path_traversal":
                validator.validate_path_traversal,

            "validate_command_execution":
                validator.validate_command_execution,

            "validate_xss_reflection":
                validator.validate_xss_reflection,

            "validate_open_redirect":
                validator.validate_open_redirect,
        }

        for plan in plans:

            method = validator_methods.get(
                plan.validator
            )

            if method is None:

                validation_results.append({
                    "path_id": plan.path_id,
                    "category": plan.category,
                    "status": "NO_VALIDATOR",
                })

                print(
                    f"      [SKIPPED] "
                    f"{plan.path_id} "
                    f"{plan.category}"
                )

                continue

            print(
                f"      [TESTING] "
                f"{plan.path_id} "
                f"{plan.category}"
            )

            result = method()

            result["path_id"] = plan.path_id
            result["category"] = plan.category
            result["severity"] = plan.severity
            result["confidence"] = plan.confidence

            validation_results.append(
                result
            )

            if result.get("validated"):

                confirmed.append(result)

                print(
                    f"      [CONFIRMED] "
                    f"{plan.path_id} "
                    f"{plan.category}"
                )

            else:

                print(
                    f"      [NOT CONFIRMED] "
                    f"{plan.path_id} "
                    f"{plan.category}"
                )

        # -----------------------------------------------------
        # 5. REPORT
        # -----------------------------------------------------

        print()
        print("[5/5] Building hacker verdict...")

        output = {
            "target": str(target_path),
            "base_url": target.base_url,
            "recon": recon,
            "plans": [
                {
                    "path_id": plan.path_id,
                    "category": plan.category,
                    "severity": plan.severity,
                    "confidence": plan.confidence,
                    "validator": plan.validator,
                }
                for plan in plans
            ],
            "validation": validation_results,
            "confirmed_attacks": len(confirmed),
        }

        output_path = Path(
            "reports/hacker_report.json"
        )

        output_path.parent.mkdir(
            exist_ok=True
        )

        with open(
            output_path,
            "w",
            encoding="utf-8",
        ) as file:

            json.dump(
                output,
                file,
                indent=4,
            )

        print()
        print("=" * 70)
        print(
            f"ATTACK PATHS DISCOVERED: "
            f"{len(recon['attack_paths'])}"
        )
        print(
            f"ATTACKS PLANNED: "
            f"{len(plans)}"
        )
        print(
            f"ATTACKS CONFIRMED: "
            f"{len(confirmed)}"
        )
        print(
            f"REPORT: "
            f"{output_path}"
        )
        print("=" * 70)

    finally:

        print()
        print("[CLEANUP] Stopping target...")

        target.stop()

        print("[DONE]")


if __name__ == "__main__":
    main()
