import ast
from scanner.rules.base import Rule


class CommandInjectionRule(Rule):

    id = "PG005"
    name = "Command Injection"
    severity = "CRITICAL"
    category = "Command Injection"

    COMMAND_FUNCTIONS = {
        "system",
        "popen",
        "run",
        "call",
        "check_call",
        "check_output",
    }

    def check(self, filepath, lines):
        findings = []

        source = "".join(lines)
        tree = ast.parse(source)

        for node in ast.walk(tree):

            if not isinstance(node, ast.Call):
                continue

            func = node.func

            # Detect os.system(...)
            if (
                isinstance(func, ast.Attribute)
                and func.attr in self.COMMAND_FUNCTIONS
            ):
                findings.append({
                    "id": self.id,
                    "file": filepath,
                    "line": node.lineno,
                    "code": ast.get_source_segment(source, node),
                })

            # Detect subprocess.run(..., shell=True)
            if (
                isinstance(func, ast.Attribute)
                and func.attr == "run"
                and isinstance(func.value, ast.Name)
                and func.value.id == "subprocess"
            ):
                for keyword in node.keywords:
                    if (
                        keyword.arg == "shell"
                        and isinstance(keyword.value, ast.Constant)
                        and keyword.value.value is True
                    ):
                        findings.append({
                            "id": self.id,
                            "file": filepath,
                            "line": node.lineno,
                            "code": ast.get_source_segment(source, node),
                        })

        return findings
