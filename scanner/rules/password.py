import ast


def check_password(tree, filepath):

    findings = []

    for node in ast.walk(tree):

        if isinstance(node, ast.Assign):

            for target in node.targets:

                if isinstance(target, ast.Name):

                    if "password" in target.id.lower():

                        findings.append({
                            "id": "PG001",
                            "file": filepath,
                            "line": node.lineno
                        })

    return findings
