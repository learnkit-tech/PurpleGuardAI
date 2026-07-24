def suggest_fix(finding):

    fixes = {
        "PG001": "Move passwords to environment variables or a secrets manager.",
        "PG002": "Replace eval() with safe parsing methods.",
        "PG003": "Remove secrets from source code and rotate exposed keys.",
        "PG004": "Use parameterized SQL queries."
    }

    return fixes.get(
        finding["id"],
        "Review this issue manually."
    )
