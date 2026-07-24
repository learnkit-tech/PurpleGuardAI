from scanner.knowledge.loader import load_vulnerabilities


def enrich_findings(findings):

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
                **vulnerability
            }

            enriched.append(result)

    return enriched
