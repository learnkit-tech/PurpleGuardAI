import ast


def check_secrets(tree, filepath):

    findings = []

    for node in ast.walk(tree):

        if isinstance(node, ast.Assign):

            for target in node.targets:

                if isinstance(target, ast.Name):

                    name = target.id.upper()

                    if any(word in name for word in [
                        "API_KEY",
                        "SECRET",
                        "TOKEN"
                    ]):

                        findings.append({
                            "id": "PG003",
                            "file": filepath,
                            "line": node.lineno
                        })

    return findings
