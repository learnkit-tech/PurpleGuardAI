import ast


def check_sql_injection(tree, filepath):

    findings = []

    for node in ast.walk(tree):

        if isinstance(node, ast.BinOp):

            if isinstance(node.op, ast.Add):

                left = node.left

                if isinstance(left, ast.Constant):

                    if isinstance(left.value, str):

                        sql_words = [
                            "SELECT",
                            "INSERT",
                            "UPDATE",
                            "DELETE"
                        ]

                        text = left.value.upper()

                        if any(word in text for word in sql_words):

                            findings.append({
                                "id": "PG004",
                                "file": filepath,
                                "line": node.lineno
                            })

    return findings
