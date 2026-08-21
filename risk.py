def calculate_risk(finding, context):
    score = 0

    if finding.get("severity") == "CRITICAL":
        score += 5
    elif finding.get("severity") == "HIGH":
        score += 4

    if context.get("public_endpoint"):
        score += 2

    if context.get("authentication_required") is False:
        score += 2

    if context.get("user_input"):
        score += 1

    return min(score, 10)
