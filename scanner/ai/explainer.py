def explain_finding(finding):

    explanations = {
        "PG001": "Hardcoded passwords can be exposed if source code is leaked.",
        "PG002": "eval() may execute attacker-controlled code.",
        "PG003": "Hardcoded secrets increase the risk of credential compromise.",
        "PG004": "String-built SQL queries may allow SQL injection."
    }

    return explanations.get(
        finding["id"],
        "No explanation available."
    )
