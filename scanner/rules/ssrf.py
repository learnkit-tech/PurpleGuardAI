import ast
from scanner.rules.base import Rule


class SSRFRule(Rule):

    id = "PG009"
    name = "SSRF"
    severity = "HIGH"
    category = "SSRF"

    # Outbound request sinks. Only the first positional argument
    # (the URL) is considered attacker-influenced. Bare names
    # cover `from urllib.request import urlopen` style imports;
    # dotted names cover fully-qualified calls.
    SSRF_SINKS = {
        "urlopen",
        "urllib.request.urlopen",
        "requests.get",
        "requests.post",
        "requests.put",
        "requests.request",
        "httpx.get",
        "httpx.post",
    }

    @staticmethod
    def _find_validated_names(tree):
        """
        Find variable names protected by a destination allowlist
        check (startswith(...) against a trusted prefix, with a
        raise/return on failure) before the request is made.

        The whole condition is walked so compound guards such as
        `if not url or not url.startswith(allowed):` are
        recognized; the bare `if not url.startswith(...)` form is
        the single-term case of the same walk.
        """

        validated = set()

        for node in ast.walk(tree):

            if not isinstance(node, ast.If):
                continue

            for condition in ast.walk(node.test):

                if not (
                    isinstance(condition, ast.UnaryOp)
                    and isinstance(condition.op, ast.Not)
                ):
                    continue

                call = condition.operand

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

            sink_name = self._resolve_sink_name(node.func)

            if sink_name not in self.SSRF_SINKS:
                continue

            if not node.args:
                continue

            argument = node.args[0]

            # A literal URL is developer-controlled.
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

    def _resolve_sink_name(self, func):
        """
        Resolve a call target to its dotted name so that both
        bare urlopen(...) and requests.get(...) are recognized.
        """

        if isinstance(func, ast.Name):
            return func.id

        if isinstance(func, ast.Attribute):
            parts = [func.attr]

            current = func.value

            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value

            if isinstance(current, ast.Name):
                parts.append(current.id)

            return ".".join(reversed(parts))

        return ""
