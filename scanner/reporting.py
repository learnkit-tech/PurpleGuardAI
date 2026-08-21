from scanner.knowledge.loader import load_vulnerabilities
from scanner.risk import RiskAnalyzer


def enrich_findings(findings):
    vulnerabilities = load_vulnerabilities()
    enriched = []

    for finding in findings:
        vulnerability = vulnerabilities.get(finding["id"])

        if vulnerability:
            result = {
                **finding,
                **vulnerability
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
