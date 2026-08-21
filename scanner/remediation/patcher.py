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

    def _generate_actual_fix(self, finding, content):
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

            # Backward-compatible fallback.
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

            remediation = finding.get("remediation", {})

            before = remediation.get("before")
            after = remediation.get("after")

            # Use the remediation information if available.
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

            # Fallback for findings containing detected code.
            detected_code = finding.get("code")

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
