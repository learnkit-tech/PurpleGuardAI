from dataclasses import dataclass


@dataclass
class PlannedAttack:
    path_id: str
    category: str
    severity: str
    confidence: float
    validator: str


class AttackPlanner:

    VALIDATORS = {
        "SQL_INJECTION": "validate_sql_behavior",
        "CODE_EXECUTION": "validate_calculator",
    }

    def plan(self, attack_paths):

        plans = []

        for path in attack_paths:

            # AttackPath objects become dictionaries when
            # PurpleGuardHacker.summary() serializes the report.
            if isinstance(path, dict):

                path_id = path.get("id")
                category = path.get("category")
                severity = path.get("severity")
                confidence = path.get("confidence")

            else:

                path_id = path.id
                category = path.category
                severity = path.severity
                confidence = path.confidence

            validator = self.VALIDATORS.get(
                category
            )

            if not validator:
                continue

            plans.append(
                PlannedAttack(
                    path_id=path_id,
                    category=category,
                    severity=severity,
                    confidence=confidence,
                    validator=validator,
                )
            )

        return plans
