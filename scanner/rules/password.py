import ast

from scanner.rules.base import Rule


class HardcodedPasswordRule(Rule):
    id = "PG001"
    name = "Hardcoded Password"
    severity = "HIGH"
    category = "Secrets Management"

    PASSWORD_NAMES = {
        "password",
        "passwd",
        "pwd",
        "user_password",
        "admin_password",
        "db_password",
    }

    SAFE_FUNCTIONS = {
        "getenv",
    }

    def check(self, filepath, lines):
        findings = []

        source = "".join(lines)

        try:
            tree = ast.parse(source)
        except SyntaxError:
            return findings

        for node in ast.walk(tree):

            if not isinstance(node, ast.Assign):
                continue

            for target in node.targets:

                if not isinstance(target, ast.Name):
                    continue

                variable_name = target.id.lower()

                if variable_name not in self.PASSWORD_NAMES:
                    continue

                # Secure environment-variable lookup:
                #
                # password = os.getenv("APP_PASSWORD")
                #
                # This is not a hardcoded password.
                if self._is_environment_lookup(node.value):
                    continue

                # Only report assignments containing a literal value.
                if isinstance(node.value, ast.Constant):
                    if isinstance(node.value.value, str):
                        findings.append({
                            "id": self.id,
                            "name": self.name,
                            "file": filepath,
                            "line": node.lineno,
                            "severity": self.severity,
                            "category": self.category,
                            "code": lines[node.lineno - 1].strip()
                        })

        return findings

    def _is_environment_lookup(self, value):
        """
        Detect calls such as:

            os.getenv("APP_PASSWORD")
            getenv("APP_PASSWORD")

        These retrieve the secret externally rather than
        hardcoding the secret in source code.
        """

        if not isinstance(value, ast.Call):
            return False

        function = value.func

        # getenv(...)
        if isinstance(function, ast.Name):
            return function.id in self.SAFE_FUNCTIONS

        # os.getenv(...)
        if isinstance(function, ast.Attribute):
            return (
                function.attr in self.SAFE_FUNCTIONS
                and isinstance(function.value, ast.Name)
                and function.value.id == "os"
            )

        return False
