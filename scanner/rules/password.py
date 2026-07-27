import ast
from scanner.rules.base import Rule


class HardcodedPasswordRule(Rule):
    id = "PG001"
    name = "Hardcoded Password"
    severity = "HIGH"
    category = "Secrets Management"

    def check(self, filepath, lines):
        findings = []

        tree = ast.parse("".join(lines))

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        if "password" in target.id.lower():
                            findings.append({
                                "id": self.id,
                                "file": filepath,
                                "line": node.lineno
                            })

        return findings

