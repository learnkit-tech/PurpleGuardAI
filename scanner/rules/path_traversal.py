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

            if isinstance(
                node,
                (ast.FunctionDef, ast.AsyncFunctionDef)
            ):
                findings.extend(
                    self._check_function(
                        node,
                        source,
                        filepath
                    )
                )

        return findings

    def _check_function(self, func_node, source, filepath):
        findings = []

        guarded_names = self._find_guarded_names(
            func_node
        )

        for node in ast.walk(func_node):

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

            argument_name = (
                argument.id
                if isinstance(argument, ast.Name)
                else None
            )

            # Already validated against a base directory
            # earlier in this function - this is the pattern
            # PurpleGuard's own remediation generates, so a
            # patched call should not be re-flagged as broken.
            if (
                argument_name
                and argument_name in guarded_names
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

    @staticmethod
    def _find_guarded_names(func_node):
        """
        Find variable names that are checked against an
        allowed base directory (is_relative_to(...), or a
        str(...).startswith(...) prefix check) with a
        raise/return on failure, before being used.
        """

        guarded = set()

        for node in ast.walk(func_node):

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

            if not isinstance(call.func, ast.Attribute):
                continue

            # if not X.is_relative_to(...):
            if call.func.attr == "is_relative_to":
                target = call.func.value

                if isinstance(target, ast.Name):
                    guarded.add(target.id)

            # if not str(X).startswith(...):
            if (
                call.func.attr == "startswith"
                and isinstance(call.func.value, ast.Call)
                and isinstance(
                    call.func.value.func,
                    ast.Name
                )
                and call.func.value.func.id == "str"
                and call.func.value.args
                and isinstance(
                    call.func.value.args[0],
                    ast.Name
                )
            ):
                guarded.add(
                    call.func.value.args[0].id
                )

        return guarded
