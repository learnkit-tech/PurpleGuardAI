import ast
from scanner.rules.base import Rule


class HardcodedSecretRule(Rule):
    id = "PG003"
    name = "Hardcoded Secret"
    severity = "HIGH"
    category = "Secrets Management"

    def check(self, filepath, lines):
        findings = []

        source = "".join(lines)
        tree = ast.parse(source)

        secret_names = [
            "API_KEY",
            "SECRET",
            "TOKEN"
        ]

        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue

            for target in node.targets:
                if not isinstance(target, ast.Name):
                    continue

                name = target.id.upper()

                if not any(word in name for word in secret_names):
                    continue

                # Only flag genuinely hardcoded string values.
                # os.getenv("TOKEN"), os.environ["TOKEN"], etc.
                # are not hardcoded secrets.
                if isinstance(node.value, ast.Constant):
                    if isinstance(node.value.value, str):
                        findings.append({
                            "id": self.id,
                            "file": filepath,
                            "line": node.lineno,
                            "code": ast.get_source_segment(
                                source,
                                node
                            ),
                        })

        return findings
