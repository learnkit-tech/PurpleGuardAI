import ast
from scanner.rules.base import Rule


class DangerousEvalRule(Rule):
    id = "PG002"
    name = "Dangerous eval()"
    severity = "CRITICAL"
    category = "Code Injection"

    def check(self, filepath, lines):
        findings = []

        source = "".join(lines)
        tree = ast.parse(source)

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if node.func.id == "eval":
                        findings.append({
                            "id": self.id,
                            "file": filepath,
                            "line": node.lineno,
                            "code": ast.get_source_segment(source, node),
                        })

        return findings
