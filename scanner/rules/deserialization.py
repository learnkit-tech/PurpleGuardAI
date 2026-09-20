import ast
from scanner.rules.base import Rule


class InsecureDeserializationRule(Rule):

    id = "PG010"
    name = "Insecure Deserialization"
    severity = "HIGH"
    category = "Insecure Deserialization"

    # Deserialization sinks that can execute attacker-controlled
    # code (pickle/dill object reconstruction). Only dotted names
    # are matched on purpose: a bare "loads" would also catch
    # json.loads, which is safe. Bare-name imports of pickle.loads
    # are therefore not detected (documented conservatism).
    DESERIALIZATION_SINKS = {
        "pickle.loads",
        "pickle.load",
        "dill.loads",
        "dill.load",
    }

    def check(self, filepath, lines):
        findings = []

        source = "".join(lines)

        try:
            tree = ast.parse(source)
        except SyntaxError:
            return findings

        for node in ast.walk(tree):

            if not isinstance(node, ast.Call):
                continue

            sink_name = self._resolve_sink_name(node.func)

            if sink_name not in self.DESERIALIZATION_SINKS:
                continue

            if not node.args:
                continue

            argument = node.args[0]

            # A literal payload is developer-controlled.
            if isinstance(argument, ast.Constant):
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
        pickle.loads(...) and _pickle.loads(...) style attribute
        chains are recognized, while bare function calls (such as
        a RestrictedUnpickler instance's .load()) are not.
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
