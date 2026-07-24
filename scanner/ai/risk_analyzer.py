def analyze_risk(finding):

    score = finding.get("score", 0)

    if score >= 9:
        return "Immediate attention required"

    if score >= 7:
        return "High priority remediation"

    return "Monitor and review"
