import ast


def check_dangerous_functions(tree, filepath):
    findings = []

    for node in ast.walk(tree):

        if isinstance(node, ast.Call):

            if isinstance(node.func, ast.Name):

                if node.func.id == "eval":

                    findings.append({
                        "file": filepath,
                        "line": node.lineno,
                        "issue": "Dangerous eval() usage",
                        "severity": "HIGH"
                    })

    return findings
