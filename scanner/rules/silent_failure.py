import ast

from scanner.rules.base import Rule


class SilentFailureRule(Rule):
    """PG011: swallowed exceptions / silent failure paths.

    A security event that is silently swallowed is invisible to
    incident response. This rule flags exception handlers whose
    entire body discards the error without logging, re-raising, or
    otherwise recording it:

        try:
            ...
        except Exception:
            pass

    Deliberately conservative: only a body consisting solely of
    `pass`, `...`, or `continue` is reported. An `except` that
    returns a value, logs, records metrics, or raises is not flagged,
    because those are legitimate handling strategies.
    """

    id = "PG011"
    name = "Swallowed Exception"
    severity = "MEDIUM"
    category = "Error Handling"

    @staticmethod
    def _is_silent(body):
        for statement in body:
            if isinstance(statement, ast.Pass):
                continue
            if isinstance(statement, ast.Continue):
                continue
            if (
                isinstance(statement, ast.Expr)
                and isinstance(statement.value, ast.Constant)
                and statement.value.value is Ellipsis
            ):
                continue
            return False

        return bool(body)

    def check(self, filepath, lines):
        findings = []

        source = "".join(lines)

        try:
            tree = ast.parse(source)
        except SyntaxError:
            return findings

        for node in ast.walk(tree):

            if not isinstance(node, ast.ExceptHandler):
                continue

            if not self._is_silent(node.body):
                continue

            findings.append({
                "id": self.id,
                "file": filepath,
                "line": node.lineno,
                "code": ast.get_source_segment(source, node),
            })

        return findings
