from scanner.ai.explainer import explain_finding
from scanner.ai.fixer import suggest_fix
from scanner.ai.risk_analyzer import analyze_risk


class PurpleGuardAI:

    def analyze(self, findings):

        results = []

        for finding in findings:

            item = finding.copy()

            item["ai_explanation"] = explain_finding(finding)
            item["recommended_fix"] = suggest_fix(finding)
            item["risk_analysis"] = analyze_risk(finding)

            results.append(item)

        return results

