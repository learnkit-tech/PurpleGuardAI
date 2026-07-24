def filter_by_severity(findings, minimum_severity):

    levels = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4
    }

    minimum_level = levels.get(
        minimum_severity.upper(),
        0
    )

    return [
        finding
        for finding in findings
        if levels.get(
            finding["severity"].upper(),
            0
        ) >= minimum_level
    ]
