class SecurityDecisionEngine:
    """
    Converts scan results into an actionable security decision.
    """

    def decide(self, report):
        findings = report.get("findings", [])
        analysis = report.get("analysis", {})

        risk = analysis.get(
            "overall_risk",
            "UNKNOWN"
        )

        risk_score = analysis.get(
            "risk_score",
            0
        )

        if not findings:
            return {
                "risk": "LOW",
                "risk_score": risk_score,
                "action": "NO_ACTION_REQUIRED",
                "auto_fix": False,
                "approval_required": False,
                "verification_required": False,
                "rollback_available": False,
                "finding_count": 0
            }

        if risk == "CRITICAL":
            action = "REMEDIATION_REQUIRED"
        elif risk == "HIGH":
            action = "REMEDIATION_RECOMMENDED"
        else:
            action = "REVIEW_RECOMMENDED"

        return {
            "risk": risk,
            "risk_score": risk_score,
            "action": action,
            "auto_fix": False,
            "approval_required": True,
            "verification_required": True,
            "rollback_available": True,
            "finding_count": len(findings)
        }
