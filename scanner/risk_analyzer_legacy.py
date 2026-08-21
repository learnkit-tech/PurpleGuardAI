class RiskAnalyzer:

    def analyze(self, findings):

        if not findings:
            return {
                "risk_score": 0,
                "overall_risk": "LOW",
                "priority": [],
                "attack_paths": []
            }

        severity_points = {
            "CRITICAL": 10,
            "HIGH": 8,
            "MEDIUM": 5,
            "LOW": 2
        }

        risk_score = 0

        for finding in findings:
            risk_score += severity_points.get(
                finding.get("severity", "LOW"),
                0
            )

        if risk_score >= 35:
            overall_risk = "CRITICAL"
        elif risk_score >= 20:
            overall_risk = "HIGH"
        elif risk_score >= 10:
            overall_risk = "MEDIUM"
        else:
            overall_risk = "LOW"


        priority = sorted(
            [
                {
                    "id": f["id"],
                    "name": f["name"],
                    "severity": f["severity"]
                }
                for f in findings
            ],
            key=lambda x: severity_points.get(
                x["severity"],
                0
            ),
            reverse=True
        )


        ids = {
            f["id"]
            for f in findings
        }

        attack_paths = []


        if "PG001" in ids and "PG002" in ids:
            attack_paths.append(
                "Hardcoded credentials combined with unsafe code execution could allow account compromise and remote code execution."
            )


        if "PG003" in ids and "PG004" in ids:
            attack_paths.append(
                "Exposed secrets combined with SQL injection risk could lead to unauthorized database access and data exposure."
            )


        if "PG001" in ids and "PG003" in ids:
            attack_paths.append(
                "Multiple exposed credentials indicate weak secrets management and increase the chance of unauthorized access."
            )


        return {
            "risk_score": risk_score,
            "overall_risk": overall_risk,
            "priority": priority,
            "attack_paths": attack_paths
        }
