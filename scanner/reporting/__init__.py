from scanner.knowledge.loader import load_vulnerabilities
from scanner.risk import RiskAnalyzer
from scanner.remediation.engine import RemediationEngine


def enrich_findings(findings):

    remediation_engine = RemediationEngine()
    vulnerabilities = load_vulnerabilities()

    enriched = []

    for finding in findings:

        vulnerability = vulnerabilities.get(
            finding["id"]
        )

        if vulnerability:

            result = {
    "id": finding["id"],
    "file": finding["file"],
    "line": finding["line"],
    **vulnerability,
    "remediation": remediation_engine.generate_fix(
        {
            "id": finding["id"],
            "file": finding["file"],
            "line": finding["line"],
            "name": vulnerability["name"]
        }
    )
}

            enriched.append(result)

    return enriched


def generate_report(findings):

    enriched = enrich_findings(findings)

    analyzer = RiskAnalyzer()

    analysis = analyzer.analyze(enriched)

    return {
        "findings": enriched,
        "analysis": analysis
    }
