def generate_summary(findings):

    total = len(findings)

    critical = len([
        f for f in findings
        if f.get("priority") == "CRITICAL"
    ])

    return {
        "total_findings": total,
        "critical_findings": critical,
        "summary": (
            f"PurpleGuardAI detected {total} issues "
            f"including {critical} critical risks."
        )
    }
