import ast


def check_dangerous_functions(tree, filepath):

    findings = []

    for node in ast.walk(tree):

        if isinstance(node, ast.Call):

            if isinstance(node.func, ast.Name):

                if node.func.id == "eval":

                    findings.append({
                        "id": "PG002",
                        "file": filepath,
                        "line": node.lineno
                    })

    return findings
