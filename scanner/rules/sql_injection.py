import ast
from scanner.rules.base import Rule


class SQLInjectionRule(Rule):

    id = "PG004"
    name = "SQL Injection"
    severity = "CRITICAL"
    category = "Injection"

    def check(self, filepath, lines):

        findings = []

        tree = ast.parse("".join(lines))

        for node in ast.walk(tree):

            if isinstance(node, ast.Assign):

                if isinstance(node.value, ast.BinOp):

                    if isinstance(node.value.op, ast.Add):

                        left = node.value.left

                        if (
                            isinstance(left, ast.Constant)
                            and isinstance(left.value, str)
                            and "select" in left.value.lower()
                        ):
                            findings.append({
                                "id": self.id,
                                "file": filepath,
                                "line": node.lineno
                            })

        return findings
