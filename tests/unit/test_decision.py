import unittest

from scanner.decision.engine import SecurityDecisionEngine


class TestSecurityDecisionEngine(unittest.TestCase):

    def setUp(self):
        self.engine = SecurityDecisionEngine()

    def test_critical_requires_remediation(self):
        report = {
            "findings": [
                {
                    "id": "PG002",
                    "severity": "CRITICAL"
                }
            ],
            "analysis": {
                "risk_score": 9.5,
                "overall_risk": "CRITICAL"
            }
        }

        decision = self.engine.decide(report)

        self.assertEqual(
            decision["risk"],
            "CRITICAL"
        )

        self.assertEqual(
            decision["action"],
            "REMEDIATION_REQUIRED"
        )

        self.assertTrue(
            decision["approval_required"]
        )

        self.assertTrue(
            decision["verification_required"]
        )

        self.assertTrue(
            decision["rollback_available"]
        )

    def test_secure_project_requires_no_action(self):
        report = {
            "findings": [],
            "analysis": {
                "risk_score": 0,
                "overall_risk": "LOW"
            }
        }

        decision = self.engine.decide(report)

        self.assertEqual(
            decision["action"],
            "NO_ACTION_REQUIRED"
        )

        self.assertFalse(
            decision["approval_required"]
        )

        self.assertFalse(
            decision["rollback_available"]
        )

        self.assertEqual(
            decision["finding_count"],
            0
        )


if __name__ == "__main__":
    unittest.main()
