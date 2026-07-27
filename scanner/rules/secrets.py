import ast
from scanner.rules.base import Rule


class HardcodedSecretRule(Rule):
    id = "PG003"
    name = "Hardcoded Secret"
    severity = "HIGH"
    category = "Secrets Management"

    def check(self, filepath, lines):
        findings = []

        tree = ast.parse("".join(lines))

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
                                "id": self.id,
                                "file": filepath,
                                "line": node.lineno
                            })

        return findings
