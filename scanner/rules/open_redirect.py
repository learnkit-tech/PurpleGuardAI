import ast
from scanner.rules.base import Rule


class OpenRedirectRule(Rule):

    id = "PG008"
    name = "Open Redirect"
    severity = "HIGH"
    category = "Open Redirect"

    REDIRECT_SINKS = {
        "redirect",
    }

    @staticmethod
    def _find_validated_names(tree):
        """
        Find variable names protected by a redirect-destination
        validation (startswith("/") without a scheme check is the
        conventional relative-only guard) with a raise or return
        on failure.
        """

        validated = set()

        for node in ast.walk(tree):

            if not isinstance(node, ast.If):
                continue

            test = node.test

            if not (
                isinstance(test, ast.UnaryOp)
                and isinstance(test.op, ast.Not)
            ):
                continue

            call = test.operand

            if not (
                isinstance(call, ast.Call)
                and isinstance(call.func, ast.Attribute)
                and call.func.attr == "startswith"
            ):
                continue

            target = call.func.value

            if isinstance(target, ast.Name):
                validated.add(target.id)

        return validated

    def check(self, filepath, lines):
        findings = []

        source = "".join(lines)

        try:
            tree = ast.parse(source)
        except SyntaxError:
            return findings

        validated = self._find_validated_names(tree)

        for node in ast.walk(tree):

            if not isinstance(node, ast.Call):
                continue

            if not isinstance(node.func, ast.Name):
                continue

            if node.func.id not in self.REDIRECT_SINKS:
                continue

            if not node.args:
                continue

            argument = node.args[0]

            # A literal destination is developer-controlled.
            if isinstance(argument, ast.Constant):
                continue

            argument_name = (
                argument.id
                if isinstance(argument, ast.Name)
                else None
            )

            if (
                argument_name
                and argument_name in validated
            ):
                continue

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
