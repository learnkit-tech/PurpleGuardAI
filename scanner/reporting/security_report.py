import json
from datetime import datetime


class SecurityReportGenerator:

    def generate(self, results):

        report = {
            "generated_at": str(datetime.now()),

            "summary": {
                "total_findings": len(
                    results.get("findings", [])
                ),
                "risk_level": self.calculate_risk(
                    results.get("findings", [])
                )
            },

            "project": results.get("project"),

            "findings": results.get("findings"),

            "attack_paths": results.get(
                "attack_graph"
            ),

            "ai_analysis": results.get(
                "analysis"
            ),

            "patches": results.get(
                "patches"
            ),

            "verification": results.get(
                "verification"
            )
        }

        return report


    def save(self, report, filename):
        with open(filename, "w") as file:
            json.dump(
                report,
                file,
                indent=4
            )


    def calculate_risk(self, findings):

        if not findings:
            return "LOW"

        critical = 0
        high = 0

        for finding in findings:
            severity = finding.get(
                "severity",
                ""
            ).upper()

            if severity == "CRITICAL":
                critical += 1

            elif severity == "HIGH":
                high += 1


        if critical:
            return "CRITICAL"

        if high:
            return "HIGH"

        return "MEDIUM"
