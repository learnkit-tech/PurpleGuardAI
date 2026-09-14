import json

from .validation.validator import LocalAttackValidator


class HackerReverification:
    """
    Replays previously confirmed Hacker validations against a
    remediated local target.

    A previously confirmed attack must stop being confirmed for
    the remediation to be considered security-effective.
    """

    VALIDATORS = {
        "validate_sql_behavior":
            "validate_sql_behavior",

        "validate_calculator":
            "validate_calculator",
    }

    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")
        self.validator = LocalAttackValidator(
            self.base_url
        )

    def verify(self, hacker_findings):
        results = []

        for finding in hacker_findings:

            validator_name = finding.validator

            method_name = self.VALIDATORS.get(
                validator_name
            )

            if not method_name:
                results.append({
                    "finding_id": finding.finding_id,
                    "path_id": finding.path_id,
                    "status": "NOT_VERIFIED",
                    "message": (
                        f"No validator registered for "
                        f"{validator_name}"
                    )
                })
                continue

            validator = getattr(
                self.validator,
                method_name,
                None
            )

            if validator is None:
                results.append({
                    "finding_id": finding.finding_id,
                    "path_id": finding.path_id,
                    "status": "NOT_VERIFIED",
                    "message": (
                        f"Validator method {method_name} "
                        f"does not exist."
                    )
                })
                continue

            validation = validator()

            blocked = not bool(
                validation.get("validated")
            )

            results.append({
                "finding_id": finding.finding_id,
                "path_id": finding.path_id,
                "category": finding.category,
                "severity": finding.severity,
                "validator": validator_name,
                "payload": validation.get("payload"),
                "validated": validation.get("validated"),
                "blocked": blocked,
                "status": (
                    "HACK_BLOCKED"
                    if blocked
                    else "HACK_STILL_WORKS"
                ),
                "evidence": validation.get("evidence"),
            })

        return results

    @staticmethod
    def verdict(results):
        if not results:
            return {
                "status": "NOT_VERIFIED",
                "message": "No Hacker validations were replayed."
            }

        all_blocked = all(
            result.get("blocked") is True
            for result in results
        )

        return {
            "status": (
                "SECURITY_VERIFIED"
                if all_blocked
                else "SECURITY_NOT_VERIFIED"
            ),
            "all_attacks_blocked": all_blocked,
            "results": results,
        }
