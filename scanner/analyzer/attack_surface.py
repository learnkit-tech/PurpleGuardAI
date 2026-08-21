from pathlib import Path

KEYWORDS = {
    "login": "Authentication",
    "signin": "Authentication",
    "auth": "Authentication",
    "register": "Registration",
    "upload": "File Upload",
    "admin": "Admin Interface",
    "password": "Password Handling",
    "token": "Token Handling",
    "api": "API Endpoint",
    "sql": "Database Access",
    "select": "Database Query",
    "insert": "Database Query",
    "update": "Database Query",
    "delete": "Database Query",
}

SUPPORTED = {
    ".py", ".js", ".ts", ".java", ".go", ".php", ".cs", ".rs"
}


def discover_attack_surface(project_path):
    findings = []

    for file in Path(project_path).rglob("*"):
        if file.suffix not in SUPPORTED:
            continue

        try:
            content = file.read_text(errors="ignore").lower()
        except Exception:
            continue

        for keyword, category in KEYWORDS.items():
            if keyword in content:
                findings.append({
                    "file": str(file),
                    "category": category,
                    "keyword": keyword
                })

    return findings
