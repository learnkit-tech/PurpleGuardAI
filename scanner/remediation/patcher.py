import ast
import os

from scanner.remediation.engine import RemediationEngine
from scanner.remediation.diff import generate_diff


class CodePatcher:
    """
    Generates safe source-code patches for PurpleGuard findings.
    """

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

        return None

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
