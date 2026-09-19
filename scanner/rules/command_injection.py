import ast
from scanner.rules.base import Rule


class CommandInjectionRule(Rule):

    id = "PG005"
    name = "Command Injection"
    severity = "CRITICAL"
    category = "Command Injection"

    # Functions that always interpret their argument as a
    # shell command line.
    SHELL_FUNCTIONS = {
        "system",
        "popen",
    }

    # Functions that only become shell-interpreted when
    # shell=True is passed.
    SUBPROCESS_FUNCTIONS = {
        "run",
        "call",
        "check_call",
        "check_output",
        "Popen",
    }

    @staticmethod
    def _owner_name(node):
        """Dotted name of the object a method is called on."""

        if isinstance(node, ast.Name):
            return node.id

        if isinstance(node, ast.Attribute):
            parent = CommandInjectionRule._owner_name(
                node.value
            )

            if parent:
                return f"{parent}.{node.attr}"

            return node.attr

        return ""

    @staticmethod
    def _has_shell_true(node):
        for keyword in node.keywords:
            if (
                keyword.arg == "shell"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is True
            ):
                return True

        return False

    def check(self, filepath, lines):
        findings = []

        source = "".join(lines)
        tree = ast.parse(source)

        for node in ast.walk(tree):

            if not isinstance(node, ast.Call):
                continue

            func = node.func

            if not isinstance(func, ast.Attribute):
                continue

            owner = self._owner_name(func.value)
            code = ast.get_source_segment(source, node)

            # os.system(...) / os.popen(...) always run a shell.
            if (
                owner in ("os", "commands")
                and func.attr in self.SHELL_FUNCTIONS
            ):
                findings.append({
                    "id": self.id,
                    "file": filepath,
                    "line": node.lineno,
                    "code": code,
                })

            # subprocess.*(..., shell=True) runs a shell.
            elif (
                owner == "subprocess"
                and func.attr in self.SUBPROCESS_FUNCTIONS
                and self._has_shell_true(node)
            ):
                findings.append({
                    "id": self.id,
                    "file": filepath,
                    "line": node.lineno,
                    "code": code,
                })

        return findings
