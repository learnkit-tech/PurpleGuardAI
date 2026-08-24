from scanner.remediation.fixes import get_fix
from scanner.remediation.diff import generate_diff


class RemediationEngine:

    def generate_fix(self, finding):

        vulnerability_id = finding["id"]

        fix = get_fix(vulnerability_id)

        # PG003 must use the variable actually detected by
        # the scanner instead of the generic API_KEY template.
        if vulnerability_id == "PG003":
            import ast

            detected_code = finding.get("code")

            if detected_code:
                try:
                    tree = ast.parse(detected_code)

                    for node in ast.walk(tree):
                        if not isinstance(node, ast.Assign):
                            continue

                        if len(node.targets) != 1:
                            continue

                        target = node.targets[0]

                        if not isinstance(target, ast.Name):
                            continue

                        variable = target.id

                        fix = {
                            **fix,
                            "before": detected_code,
                            "after": (
                                "import os\\n"
                                f'{variable} = os.getenv("{variable}")'
                            )
                        }

                        break

                except SyntaxError:
                    pass

        patch = generate_diff(
            fix["before"],
            fix["after"]
        )

        return {
            "file": finding["file"],
            "line": finding["line"],
            "vulnerability": finding.get(
                "name",
                fix["title"]
            ),
            "fix_title": fix["title"],
            "before": fix["before"],
            "after": fix["after"],
            "patch": patch
        }
