import ast
from scanner.rules.base import Rule


class PathTraversalRule(Rule):

    id = "PG006"
    name = "Path Traversal"
    severity = "HIGH"
    category = "Path Traversal"

    FILE_FUNCTIONS = {
        "open",
        "remove",
        "unlink",
        "rename",
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

            func = node.func
            name = ""

            if isinstance(func, ast.Name):
                name = func.id
            elif isinstance(func, ast.Attribute):
                name = func.attr

            if name not in self.FILE_FUNCTIONS:
                continue

            if not node.args:
                continue

            argument = node.args[0]

            # A literal path is not attacker-controlled.
            if isinstance(argument, ast.Constant):
                continue

            findings.append({
                "id": self.id,
                "file": filepath,
                "line": node.lineno,
                "code": ast.get_source_segment(source, node),
            })

        return findings
