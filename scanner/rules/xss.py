import ast
from scanner.rules.base import Rule


class XSSRule(Rule):

    id = "PG007"
    name = "Cross-Site Scripting"
    severity = "HIGH"
    category = "Cross-Site Scripting"

    # Calls that place content directly into an HTTP response
    # body without template auto-escaping.
    RESPONSE_SINKS = {
        "Response",
        "make_response",
        "render_template_string",
        "Markup",
    }

    @staticmethod
    def _name_of(node):
        if isinstance(node, ast.Name):
            return node.id

        if isinstance(node, ast.Attribute):
            parent = XSSRule._name_of(node.value)

            if parent:
                return f"{parent}.{node.attr}"

            return node.attr

        return ""

    @staticmethod
    def _is_escaped(argument, sanitized):
        """
        An argument is considered escaped when it is wrapped in an
        escape() call at the sink, or when every variable it uses
        was protected by an escape() guard with a raise/return on
        failure.
        """

        escape_functions = {
            "markupsafe.escape",
            "escape",
            "html.escape",
        }

        for node in ast.walk(argument):

            if isinstance(node, ast.Call):

                if XSSRule._name_of(node.func) in escape_functions:
                    return True

        names = [
            node
            for node in ast.walk(argument)
            if isinstance(node, ast.Name)
        ]

        return bool(names) and all(
            name.id in sanitized
            for name in names
        )

    @staticmethod
    def _find_sanitized_names(tree):
        """
        Find variable names protected by an escaping check
        (markupsafe.escape / html.escape) with a raise or
        return on failure.
        """

        sanitized = set()

        escape_functions = {
            "markupsafe.escape",
            "escape",
            "html.escape",
        }

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

            if not isinstance(call, ast.Call):
                continue

            call_name = XSSRule._name_of(call.func)

            if call_name not in escape_functions:
                continue

            if not call.args:
                continue

            argument = call.args[0]

            if isinstance(argument, ast.Name):
                sanitized.add(argument.id)

        return sanitized

    def check(self, filepath, lines):
        findings = []

        source = "".join(lines)

        try:
            tree = ast.parse(source)
        except SyntaxError:
            return findings

        sanitized = self._find_sanitized_names(tree)

        for node in ast.walk(tree):

            if not isinstance(node, ast.Call):
                continue

            if not isinstance(node.func, ast.Name):
                continue

            if node.func.id not in self.RESPONSE_SINKS:
                continue

            for argument in node.args:

                if isinstance(argument, ast.Constant):
                    continue

                if self._is_escaped(
                    argument,
                    sanitized
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

                break

        return findings
