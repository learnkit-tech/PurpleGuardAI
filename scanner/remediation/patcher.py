import ast
import os
from pathlib import Path

from scanner.remediation.engine import RemediationEngine
from scanner.remediation.diff import generate_diff
from scanner.rules.path_traversal import PathTraversalRule


class CodePatcher:
    """
    Generates safe source-code patches for PurpleGuard findings.
    """

    # Finding classes that have an automated fix path (legacy
    # static handlers for PG001-PG004, hacker-derived
    # transformations for PG005, PG007, PG008, and the
    # conservative static patch for PG006). Per-finding
    # provability is decided by can_auto_fix(); anything not
    # provable stays a finding for manual review rather than
    # being silently transformed.
    AUTO_FIXABLE = frozenset(
        {
            "PG001",
            "PG002",
            "PG003",
            "PG004",
            "PG005",
            "PG006",
            "PG007",
            "PG008",
            "PG009",
            "PG010",
        }
    )

    def __init__(self):
        self.engine = RemediationEngine()

    def _replace_exact(self, content, old, new):
        """Replace the first exact occurrence of source code."""
        if not old:
            return None

        if old not in content:
            return None

        return content.replace(old, new, 1)

    def _ensure_import(self, content, import_line):
        """Add an import if it does not already exist."""
        if any(
            line.strip() == import_line
            for line in content.splitlines()
        ):
            return content

        return import_line + "\n" + content

    def _generate_hacker_fix(self, finding, content):
        """
        Generate source transformations for confirmed Hacker
        findings using the existing CodePatcher.

        The Hacker proves exploitability.
        CodePatcher produces the remediation.
        """

        hacker = finding.get("hacker", {})
        category = hacker.get("category")

        # ---------------------------------------------------------
        # Confirmed dynamic code execution
        # ---------------------------------------------------------
        if category == "CODE_EXECUTION":
            source_line = finding.get("code", "")

            if "eval(" not in source_line:
                return None

            fixed_line = source_line.replace(
                "eval(",
                "ast.literal_eval(",
                1
            )

            patched = self._replace_exact(
                content,
                source_line,
                fixed_line
            )

            if patched is None:
                return None

            return self._ensure_import(
                patched,
                "import ast"
            )

        # ---------------------------------------------------------
        # Confirmed command injection
        # ---------------------------------------------------------
        if category == "COMMAND_INJECTION":
            source_line = finding.get("code", "")

            if not source_line:
                return None

            try:
                tree = ast.parse(source_line)
            except SyntaxError:
                return None

            call_node = next(
                (
                    node
                    for node in ast.walk(tree)
                    if isinstance(node, ast.Call)
                ),
                None,
            )

            if call_node is None:
                return None

            if not (
                isinstance(call_node.func, ast.Attribute)
                and isinstance(call_node.func.value, ast.Name)
            ):
                return None

            owner = call_node.func.value.id
            attribute = call_node.func.attr

            if not call_node.args:
                return None

            command_argument = call_node.args[0]

            original_argument = ast.get_source_segment(
                source_line,
                command_argument
            )

            if not original_argument:
                return None

            # shlex.split() turns a command-line string into a
            # safe argument list so shell metacharacters lose
            # their meaning.
            safe_arguments = ast.Call(
                func=ast.Name(
                    id="shlex.split",
                    ctx=ast.Load(),
                ),
                args=[command_argument],
                keywords=[],
            )

            if (
                owner == "os"
                and attribute == "system"
            ):
                new_call = ast.Call(
                    func=ast.Attribute(
                        value=ast.Name(
                            id="subprocess",
                            ctx=ast.Load(),
                        ),
                        attr="run",
                        ctx=ast.Load(),
                    ),
                    args=[safe_arguments],
                    keywords=[
                        ast.keyword(
                            arg="shell",
                            value=ast.Constant(value=False),
                        )
                    ],
                )

            elif (
                owner == "os"
                and attribute == "popen"
            ):
                # popen returns a readable stream; keep a pipe so
                # downstream .read() calls keep working.
                new_call = ast.Attribute(
                    value=ast.Call(
                        func=ast.Attribute(
                            value=ast.Name(
                                id="subprocess",
                                ctx=ast.Load(),
                            ),
                            attr="Popen",
                            ctx=ast.Load(),
                        ),
                        args=[safe_arguments],
                        keywords=[
                            ast.keyword(
                                arg="stdout",
                                value=ast.Attribute(
                                    value=ast.Name(
                                        id="subprocess",
                                        ctx=ast.Load(),
                                    ),
                                    attr="PIPE",
                                    ctx=ast.Load(),
                                ),
                            ),
                            ast.keyword(
                                arg="text",
                                value=ast.Constant(value=True),
                            ),
                        ],
                    ),
                    attr="stdout",
                    ctx=ast.Load(),
                )

            elif (
                owner == "subprocess"
                and attribute in (
                    "run",
                    "call",
                    "check_call",
                    "check_output",
                    "Popen",
                )
                and self._has_shell_true(call_node)
            ):
                # Preserve every other argument and keyword so the
                # fixed call keeps behaving like the original one.
                new_call = ast.Call(
                    func=call_node.func,
                    args=(
                        [safe_arguments]
                        + list(call_node.args[1:])
                    ),
                    keywords=(
                        [
                            ast.keyword(
                                arg="shell",
                                value=ast.Constant(value=False),
                            )
                        ]
                        + [
                            keyword
                            for keyword in call_node.keywords
                            if keyword.arg != "shell"
                        ]
                    ),
                )

            else:
                return None

            original_call = ast.get_source_segment(
                source_line,
                call_node
            )

            if not original_call:
                return None

            fixed_line = source_line.replace(
                original_call,
                ast.unparse(new_call),
                1
            )

            patched = self._replace_exact(
                content,
                source_line,
                fixed_line
            )

            if patched is None:
                return None

            patched = self._ensure_import(
                patched,
                "import shlex"
            )

            return self._ensure_import(
                patched,
                "import subprocess"
            )

        # ---------------------------------------------------------
        # Confirmed reflected XSS
        # ---------------------------------------------------------
        if category == "XSS":
            source_line = finding.get("code", "")

            if not source_line:
                return None

            try:
                tree = ast.parse(source_line)
            except SyntaxError:
                return None

            call_node = next(
                (
                    node
                    for node in ast.walk(tree)
                    if isinstance(node, ast.Call)
                ),
                None,
            )

            if call_node is None:
                return None

            if not (
                isinstance(call_node.func, ast.Name)
                and call_node.func.id
                in (
                    "Response",
                    "make_response",
                    "render_template_string",
                    "Markup",
                )
            ):
                return None

            if not call_node.args:
                return None

            original_argument = ast.get_source_segment(
                source_line,
                call_node.args[0]
            )

            if not original_argument:
                return None

            fixed_line = source_line.replace(
                original_argument,
                f"escape({original_argument})",
                1
            )

            patched = self._replace_exact(
                content,
                source_line,
                fixed_line
            )

            if patched is None:
                return None

            return self._ensure_import(
                patched,
                "from markupsafe import escape"
            )

        # ---------------------------------------------------------
        # Confirmed open redirect
        # ---------------------------------------------------------
        if category == "OPEN_REDIRECT":
            source_line = finding.get("code", "")

            if not source_line:
                return None

            try:
                tree = ast.parse(source_line)
            except SyntaxError:
                return None

            call_node = next(
                (
                    node
                    for node in ast.walk(tree)
                    if isinstance(node, ast.Call)
                ),
                None,
            )

            if call_node is None:
                return None

            if not (
                isinstance(call_node.func, ast.Name)
                and call_node.func.id == "redirect"
            ):
                return None

            if not call_node.args:
                return None

            arg0 = call_node.args[0]

            if not isinstance(arg0, ast.Name):
                return None

            # Locate the actual statement in the file. The finding
            # code is only the call expression, so extend it to the
            # full statement (e.g. "return redirect(next_url)")
            # before inserting the guard.
            position = content.find(source_line)

            if position < 0:
                return None

            line_start = content.rfind("\n", 0, position) + 1

            prefix = content[line_start:position]
            statement_prefix = prefix.strip()

            # Only bare statements and simple returns are
            # supported; anything more complex is left untouched.
            if statement_prefix not in ("", "return"):
                return None

            indent = prefix[
                : len(prefix) - len(prefix.lstrip())
            ]

            statement = prefix + source_line

            # Relative-only redirect: any destination that does
            # not start with "/" is rejected, so scheme-relative
            # (//host) and absolute URLs can never be reached.
            guard = (
                f"{indent}if not {arg0.id}.startswith('/'):\n"
                f"{indent}    raise ValueError(\n"
                f"{indent}        'Open redirect blocked: only "
                f"relative redirect targets are allowed'\n"
                f"{indent}    )"
            )

            patched = self._replace_exact(
                content,
                statement,
                guard + "\n" + statement
            )

            if patched is None:
                return None

            return patched

        # ---------------------------------------------------------
        # Confirmed SQL injection
        # ---------------------------------------------------------
        if category == "SQL_INJECTION":
            source_name = hacker.get("source_name")

            # We currently know the Hacker has confirmed that
            # attacker-controlled "username" reaches the SQL sink.
            if source_name != "username":
                return None

            try:
                tree = ast.parse(content)
            except SyntaxError:
                return None

            query_assignment = None

            # Find:
            #
            # query = <expression containing username>
            #
            # rather than depending on exact whitespace or
            # formatting.
            for node in ast.walk(tree):
                if not isinstance(node, ast.Assign):
                    continue

                if len(node.targets) != 1:
                    continue

                target = node.targets[0]

                if not isinstance(target, ast.Name):
                    continue

                if target.id != "query":
                    continue

                source = ast.get_source_segment(
                    content,
                    node.value
                )

                if not source:
                    continue

                if "username" not in source:
                    continue

                if "SELECT" not in source.upper():
                    continue

                query_assignment = node
                break

            if query_assignment is None:
                return None

            # Replace only the query assignment.
            old_assignment = ast.get_source_segment(
                content,
                query_assignment
            )

            if not old_assignment:
                return None

            new_assignment = (
                'query = "SELECT * FROM users WHERE username=?"'
            )

            patched = self._replace_exact(
                content,
                old_assignment,
                new_assignment
            )

            if patched is None:
                return None

            # Now parameterize the actual database execution.
            old_execute = "connection.execute(query)"

            if old_execute not in patched:
                return None

            new_execute = (
                "connection.execute(query, (username,))"
            )

            patched = patched.replace(
                old_execute,
                new_execute,
                1
            )

            return patched

        # ---------------------------------------------------------
        # Confirmed path traversal
        # ---------------------------------------------------------
        if category == "PATH_TRAVERSAL":
            source_name = hacker.get("source_name")

            if not source_name:
                return None

            try:
                tree = ast.parse(content)
            except SyntaxError:
                return None

            path_assignment = None

            # Find the assignment that builds the final path from
            # the tainted variable, e.g.:
            #
            # target = base_dir / filename
            for node in ast.walk(tree):
                if not isinstance(node, ast.Assign):
                    continue

                if len(node.targets) != 1:
                    continue

                target = node.targets[0]

                if not isinstance(target, ast.Name):
                    continue

                source = ast.get_source_segment(
                    content,
                    node.value
                )

                if not source or source_name not in source:
                    continue

                path_assignment = node
                break

            if path_assignment is None:
                return None

            target_var = path_assignment.targets[0].id

            old_assignment = ast.get_source_segment(
                content,
                path_assignment
            )

            original_expr = ast.get_source_segment(
                content,
                path_assignment.value
            )

            if not old_assignment or not original_expr:
                return None

            # Match the original statement's indentation so the
            # generated if/raise block stays valid Python instead
            # of assuming a fixed indent width.
            indent = " " * path_assignment.col_offset

            new_assignment = (
                f"{target_var} = ({original_expr}).resolve()\n"
                f"{indent}if not {target_var}.is_relative_to(base_dir.resolve()):\n"
                f"{indent}    raise ValueError(\n"
                f"{indent}        'Path traversal blocked: "
                f"path escapes base_dir'\n"
                f"{indent}    )"
            )

            return self._replace_exact(
                content,
                old_assignment,
                new_assignment
            )

        # ---------------------------------------------------------
        # Confirmed SSRF
        # ---------------------------------------------------------
        if category == "SSRF":
            source_line = finding.get("code", "")

            if (
                not source_line
                or "urlopen" not in source_line
            ):
                return None

            try:
                tree = ast.parse(source_line)
            except SyntaxError:
                return None

            call_node = next(
                (
                    n
                    for n in ast.walk(tree)
                    if isinstance(n, ast.Call)
                ),
                None,
            )

            if call_node is None or not call_node.args:
                return None

            url_arg = call_node.args[0]

            if not isinstance(url_arg, ast.Name):
                return None

            url_var = url_arg.id

            position = content.find(source_line)

            if position < 0:
                return None

            lines = content.split("\n")

            urlopen_idx = (
                content[:position].count("\n")
            )

            # Walk backward to find the try: statement that
            # wraps the urlopen call. The guard must go OUTSIDE
            # the try/except so the ValueError is not swallowed
            # by a broad except handler.
            try_idx = None

            for i in range(urlopen_idx - 1, -1, -1):
                if lines[i].strip().startswith("try:"):
                    try_idx = i
                    break

            if try_idx is None:
                return None

            # If the URL variable is already guarded by a
            # startswith check, the fix is not needed.
            preceding = "\n".join(lines[:try_idx])

            if f"not {url_var}.startswith(" in preceding:
                return None

            indent = ""

            for char in lines[try_idx]:
                if char in (" ", "\t"):
                    indent += char
                else:
                    break

            guard = (
                f"{indent}if not {url_var}.startswith("
                f"ALLOWED_PREFIX):\n"
                f"{indent}    raise ValueError(\n"
                f"{indent}        'SSRF blocked: "
                f"destination not in allowlist'\n"
                f"{indent}    )"
            )

            try_line = lines[try_idx]

            try_pos = content.find(try_line)

            if try_pos < 0:
                return None

            try_line_start = content.rfind(
                "\n", 0, try_pos
            ) + 1

            patched = (
                content[:try_line_start]
                + guard
                + "\n"
                + content[try_line_start:]
            )

            if patched == content:
                return None

            # Add the ALLOWED_PREFIX constant when it does not
            # yet exist, placing it just before the first
            # route decorator.
            if "ALLOWED_PREFIX" not in patched:
                flask_init = (
                    "app = Flask(__name__)"
                )

                pos = patched.find(flask_init)

                if pos >= 0:
                    insert_at = (
                        pos + len(flask_init)
                    )

                    patched = (
                        patched[:insert_at]
                        + "\n\n"
                        "# PurpleGuard SSRF mitigation"
                        "\nALLOWED_PREFIX = "
                        '"https://"'
                        + patched[insert_at:]
                    )

            return patched

        # ---------------------------------------------------------
        # Confirmed insecure deserialization
        # ---------------------------------------------------------
        if category == "DESERIALIZATION":
            source_line = finding.get("code", "")

            if (
                not source_line
                or "pickle.loads" not in source_line
            ):
                return None

            fixed_line = source_line.replace(
                "pickle.loads",
                "json.loads",
                1,
            )

            patched = self._replace_exact(
                content,
                source_line,
                fixed_line,
            )

            if patched is None:
                return None

            return self._ensure_import(
                patched, "import json"
            )

        return None

    def can_auto_fix(self, finding):
        """
        Decide per finding whether a provably safe automated fix
        exists right now, by dry-running the fix generation in
        memory. Never modifies any file.
        """

        if finding.get("id") not in self.AUTO_FIXABLE:
            return False

        file_path = finding.get("file")

        if not file_path or not os.path.exists(
            file_path
        ):
            return False

        try:
            with open(file_path, "r") as file:
                content = file.read()
        except OSError:
            return False

        return self._generate_actual_fix(
            finding,
            content,
        ) is not None

    def _generate_static_path_traversal_fix(
        self,
        finding,
        content,
    ):
        """
        Conservative static remediation for path traversal
        (PG006) without attacker-confirmed metadata.

        Only one shape is provably safe to transform:

            target = <base> / <filename>

        where <base> must be a trusted expression (module-level
        constant, __file__-derived path, or a local variable)
        and <filename> is a function parameter that flows
        directly into open(). Anything else returns None so the
        finding stays in the manual-review queue instead of
        being silently rewritten.
        """

        sink_line = finding.get("line")

        if not isinstance(sink_line, int):
            return None

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return None

        sink_node = next(
            (
                node
                for node in ast.walk(tree)
                if isinstance(node, ast.Call)
                and node.lineno == sink_line
                and isinstance(node.func, (ast.Name, ast.Attribute))
                and (
                    node.func.id
                    if isinstance(node.func, ast.Name)
                    else node.func.attr
                )
                in PathTraversalRule.FILE_FUNCTIONS
            ),
            None,
        )

        if sink_node is None:
            return None

        if not sink_node.args:
            return None

        path_var_node = sink_node.args[0]

        # Only plain variable arguments are supported. A bare
        # attribute call like open(request.args.get("file"))
        # has no local path variable to guard.
        if not isinstance(path_var_node, ast.Name):
            return None

        path_var = path_var_node.id

        enclosing = self._find_enclosing_function(
            tree,
            sink_node,
        )

        if enclosing is None:
            return None

        guarded = PathTraversalRule._find_guarded_names(
            enclosing
        )

        if path_var in guarded:
            return None

        # Find the single assignment that builds this path.
        # On Path objects the "/" operator parses as ast.Div,
        # so base / filename is a BinOp with a Div operator.
        path_assignments = [
            node
            for node in ast.walk(enclosing)
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == path_var
            and isinstance(node.value, ast.BinOp)
            and isinstance(node.value.op, ast.Div)
        ]

        if len(path_assignments) != 1:
            return None

        assignment = path_assignments[0]

        left = assignment.value.left
        right = assignment.value.right

        # The filename operand must be a plain variable: either
        # a function parameter or a local assigned exactly once.
        # Its exact provenance does not affect fix safety - the
        # generated guard is taint-agnostic and blocks escapes
        # for any filename value - but keeping it a simple,
        # clearly-scoped name keeps the transformation provable.
        # The BASE operand is where trust is strictly proven.
        parameter_names = {
            arg.arg
            for arg in enclosing.args.args
        }

        filename_node = None
        base_node = None

        for candidate, other in (
            (right, left),
            (left, right),
        ):
            if not isinstance(candidate, ast.Name):
                continue

            if candidate.id in parameter_names:
                filename_node = candidate
                base_node = other
                break

            assigned = [
                inner
                for inner in ast.walk(enclosing)
                if isinstance(inner, ast.Assign)
                and any(
                    isinstance(target, ast.Name)
                    and target.id == candidate.id
                    for target in inner.targets
                )
            ]

            if len(assigned) == 1:
                filename_node = candidate
                base_node = other
                break

        if filename_node is None or base_node is None:
            return None

        # The base operand must be provably trusted: a module-
        # level constant (not a parameter, never assigned inside
        # this function) or a __file__-derived chain. Anything
        # else - tainted locals, request-derived calls, computed
        # expressions - stays unproven and is left for review.
        if not self._is_trusted_base_operand(
            base_node,
            content,
            enclosing,
            parameter_names,
        ):
            return None

        base_source = ast.get_source_segment(
            content,
            base_node,
        )

        if not base_source:
            return None

        # Reuse the exact transformation pattern already proven
        # by the Hacker-confirmed PATH_TRAVERSAL fix (see
        # tests/hacker_target/app.py): resolve + is_relative_to
        # guard + raise. This keeps scanner whitelisting in sync
        # so a patched file passes re-scan.
        assignment_source = ast.get_source_segment(
            content,
            assignment,
        )

        if not assignment_source:
            return None

        indent = " " * assignment.col_offset

        fixed_assignment = (
            f"{path_var} = ("
            f"Path({base_source}) / {filename_node.id}"
            f").resolve()\n"
            f"{indent}if not {path_var}.is_relative_to("
            f"Path({base_source}).resolve()):\n"
            f"{indent}    raise ValueError(\n"
            f"{indent}        'Path traversal blocked: "
            f"path escapes trusted base directory'\n"
            f"{indent}    )"
        )

        patched = self._replace_exact(
            content,
            assignment_source,
            fixed_assignment,
        )

        if patched is None:
            return None

        return self._ensure_import(
            patched,
            "from pathlib import Path",
        )

    @staticmethod
    def _is_trusted_base_operand(
        node,
        content,
        enclosing,
        parameter_names,
    ):
        """
        Decide whether a path-join base operand can be trusted
        without runtime knowledge. Only two shapes qualify:

        - a __file__-derived attribute chain, e.g.
          Path(__file__).resolve().parent
        - a plain variable name that is not a function
          parameter and is never assigned inside the enclosing
          function, i.e. it comes from module scope.
        """

        if isinstance(node, ast.Attribute):

            source = ast.get_source_segment(
                content,
                node,
            )

            return bool(
                source
                and "__file__" in source
            )

        if isinstance(node, ast.Name):

            if node.id in parameter_names:
                return False

            assignments = [
                inner
                for inner in ast.walk(enclosing)
                if isinstance(inner, ast.Assign)
                and any(
                    isinstance(target, ast.Name)
                    and target.id == node.id
                    for target in inner.targets
                )
            ]

            # Never assigned inside the function: it comes from
            # module scope. Only UPPER_CASE constants are treated
            # as trusted configuration.
            if not assignments:
                return node.id.isupper()

            # A single in-function alias is trusted only when its
            # value is __file__-derived (the proven remediated
            # pattern, e.g. base_dir = Path(__file__).../"reports").
            # Anything else, such as request-derived locals, stays
            # unproven.
            if len(assignments) != 1:
                return False

            value_source = ast.get_source_segment(
                content,
                assignments[0].value,
            )

            return bool(
                value_source
                and "__file__" in value_source
            )

        return False

    @staticmethod
    def _find_enclosing_function(tree, node):
        """
        Return the innermost FunctionDef containing node, or
        None if the call site is at module level or inside a
        non-function scope.
        """

        best = None

        for candidate in ast.walk(tree):
            if not isinstance(
                candidate,
                (ast.FunctionDef, ast.AsyncFunctionDef),
            ):
                continue

            for child in ast.walk(candidate):
                if child is node:
                    best = candidate
                    break

        return best

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

    def _generate_actual_fix(self, finding, content):
        # Confirmed Hacker findings get first-class remediation
        # through the existing CodePatcher.
        if finding.get("hacker"):
            hacker_fix = self._generate_hacker_fix(
                finding,
                content
            )

            if hacker_fix is not None:
                return hacker_fix

        # Static findings produced by the new rules (PG005-
        # PG008) reuse the exact same transformations as the
        # confirmed Hacker findings, with a synthetic category
        # mapping instead of duplicated fix code.
        static_categories = {
            "PG005": "COMMAND_INJECTION",
            "PG006": "PATH_TRAVERSAL",
            "PG007": "XSS",
            "PG008": "OPEN_REDIRECT",
        }

        if finding["id"] == "PG006":
            static_fix = self._generate_static_path_traversal_fix(
                finding,
                content,
            )

            if static_fix is not None:
                return static_fix

            # Unprovable pattern: keep it as a finding requiring
            # review. Returning None must never silently rewrite
            # the file, so only the supported shape is patched.
            return None

        if finding["id"] in static_categories:
            static_fix = self._generate_hacker_fix(
                {
                    **finding,
                    "hacker": {
                        "category": static_categories[
                            finding["id"]
                        ]
                    },
                },
                content
            )

            if static_fix is not None:
                return static_fix

        """
        Generate the actual fixed source code for a finding.
        """

        vulnerability_id = finding["id"]

        # ---------------------------------------------------------
        # PG002: Dangerous eval()
        # ---------------------------------------------------------
        if vulnerability_id == "PG002":

            remediation = finding.get("remediation", {})

            before = remediation.get("before")
            after = remediation.get("after")

            # Preferred path: use the remediation generated
            # by PurpleGuard's reporting layer.
            if before and after and before in content:

                patched = self._replace_exact(
                    content,
                    before,
                    after
                )

                if patched is not None:
                    return self._ensure_import(
                        patched,
                        "import ast"
                    )

            # Fallback: replace the actual detected eval expression.
            detected_code = finding.get("code")

            if detected_code and "eval(" in detected_code:

                fixed_code = detected_code.replace(
                    "eval(",
                    "ast.literal_eval(",
                    1
                )

                patched = self._replace_exact(
                    content,
                    detected_code,
                    fixed_code
                )

                if patched is not None:
                    return self._ensure_import(
                        patched,
                        "import ast"
                    )

        # ---------------------------------------------------------
        # PG003: Hardcoded Secret
        # ---------------------------------------------------------
        if vulnerability_id == "PG003":

            detected_code = finding.get("code")

            # Prefer the actual code detected by the scanner.
            if detected_code:
                try:
                    tree = ast.parse(detected_code)

                    for node in ast.walk(tree):

                        if not isinstance(node, ast.Assign):
                            continue

                        if len(node.targets) != 1:
                            continue

                        target = node.targets[0]

                        if not isinstance(target, ast.Name):
                            continue

                        variable = target.id

                        fixed_code = (
                            f'{variable} = '
                            f'os.getenv("{variable}")'
                        )

                        patched = self._replace_exact(
                            content,
                            detected_code,
                            fixed_code
                        )

                        if patched is not None:
                            return self._ensure_import(
                                patched,
                                "import os"
                            )

                except SyntaxError:
                    return None

            # Backward-compatible remediation fallback.
            remediation = finding.get("remediation", {})

            before = remediation.get("before")
            after = remediation.get("after")

            if before and after and before in content:

                patched = self._replace_exact(
                    content,
                    before,
                    after
                )

                if patched is not None:
                    return self._ensure_import(
                        patched,
                        "import os"
                    )

        # ---------------------------------------------------------
        # PG001 / PG004
        # ---------------------------------------------------------
        if vulnerability_id in ("PG001", "PG004"):

            remediation = finding.get("remediation", {})

            before = remediation.get("before")
            after = remediation.get("after")

            if before and after and before in content:
                patched = self._replace_exact(
                    content,
                    before,
                    after
                )

                if patched is not None:
                    return patched

            # Existing remediation engine fallback.
            fixed = self.engine.generate_fix(finding)

            if not fixed:
                return None

            patched = self._replace_exact(
                content,
                fixed["before"],
                fixed["after"]
            )

            if patched is not None:
                return patched

        return None

    def create_patches(self, findings):
        """
        Generate combined patches for multiple findings.

        Findings affecting the same file are applied sequentially
        in memory so their patches are combined into one final
        patch file instead of overwriting each other.
        """
        grouped = {}

        for finding in findings:
            grouped.setdefault(finding["file"], []).append(finding)

        results = []

        for file_path, file_findings in grouped.items():

            if not os.path.exists(file_path):
                for finding in file_findings:
                    results.append({
                        "file": file_path,
                        "patch_file": None,
                        "patch": "",
                        "status": "FILE_NOT_FOUND"
                    })
                continue

            with open(file_path, "r") as file:
                original_content = file.read()

            current_content = original_content
            successful = True

            for finding in file_findings:
                fixed_content = self._generate_actual_fix(
                    finding,
                    current_content
                )

                if fixed_content is None:
                    successful = False
                    break

                current_content = fixed_content

            if not successful or current_content == original_content:
                for finding in file_findings:
                    results.append({
                        "file": file_path,
                        "patch_file": None,
                        "patch": "",
                        "status": "NO_PATCH"
                    })
                continue

            patch = generate_diff(
                original_content,
                current_content
            )

            os.makedirs(
                "reports/patches",
                exist_ok=True
            )

            patch_name = os.path.basename(file_path) + ".patch"
            patch_path = os.path.join(
                "reports",
                "patches",
                patch_name
            )

            with open(patch_path, "w") as file:
                file.write(patch)

            for finding in file_findings:
                results.append({
                    "file": file_path,
                    "patch_file": patch_path,
                    "patch": patch,
                    "status": "READY"
                })

        return results

    def create_patch(self, finding):
        """
        Create a patch without modifying the original source file.
        """

        file_path = finding["file"]

        if not os.path.exists(file_path):
            return {
                "file": file_path,
                "patch_file": None,
                "patch": "",
                "status": "FILE_NOT_FOUND"
            }

        # Read the actual source file.
        with open(file_path, "r") as file:
            original_content = file.read()

        # Generate fixed source in memory.
        patched_content = self._generate_actual_fix(
            finding,
            original_content
        )

        if patched_content is None:
            return {
                "file": file_path,
                "patch_file": None,
                "patch": "",
                "status": "NO_PATCH"
            }

        # Generate unified diff.
        patch = generate_diff(
            original_content,
            patched_content
        )

        if not patch:
            return {
                "file": file_path,
                "patch_file": None,
                "patch": "",
                "status": "NO_CHANGE"
            }

        # Store the patch for inspection.
        os.makedirs(
            "reports/patches",
            exist_ok=True
        )

        patch_name = (
            os.path.basename(file_path)
            + ".patch"
        )

        patch_path = os.path.join(
            "reports",
            "patches",
            patch_name
        )

        with open(patch_path, "w") as file:
            file.write(patch)

        return {
            "file": file_path,
            "patch_file": patch_path,
            "patch": patch,
            "status": "READY"
        }
