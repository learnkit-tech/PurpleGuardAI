import os
import shutil

from scanner.remediation.patcher import CodePatcher
from scanner.engine import SecurityScanner
from scanner.verification.engine import VerificationEngine


class RemediationWorkflow:

    def __init__(self, project_path):
        self.project_path = project_path
        self.patcher = CodePatcher()
        self.verifier = VerificationEngine()

    def apply_patches(self, findings, approved=False):
        """
        Apply grouped remediation patches safely.

        Findings belonging to the same file are combined into one
        in-memory transformation before the file is modified.

        Each applied change records the original source, updated source,
        generated diff, backup path, patch file, and finding IDs so the
        frontend can provide a complete engineering change record.
        """

        if not approved:
            return {
                "status": "REJECTED",
                "message": "Approval is required before applying fixes."
            }

        results = []

        grouped = {}

        for finding in findings:
            grouped.setdefault(
                finding["file"],
                []
            ).append(finding)

        for file_path, file_findings in grouped.items():

            file_path = os.path.abspath(file_path)

            if not os.path.exists(file_path):
                results.append({
                    "file": file_path,
                    "status": "FILE_NOT_FOUND",
                    "findings": [
                        finding.get("id")
                        for finding in file_findings
                    ]
                })
                continue

            with open(file_path, "r") as file:
                original = file.read()

            current = original
            successful = True

            for finding in file_findings:

                fixed = self.patcher._generate_actual_fix(
                    finding,
                    current
                )

                if fixed is None:
                    successful = False
                    break

                current = fixed

            if not successful:
                results.append({
                    "file": file_path,
                    "status": "FAILED",
                    "findings": [
                        finding.get("id")
                        for finding in file_findings
                    ],
                    "original_source": original,
                    "updated_source": current,
                    "patch": ""
                })
                continue

            if current == original:
                results.append({
                    "file": file_path,
                    "status": "NO_CHANGE",
                    "findings": [
                        finding.get("id")
                        for finding in file_findings
                    ],
                    "original_source": original,
                    "updated_source": current,
                    "patch": ""
                })
                continue

            # Generate the complete combined diff.
            from scanner.remediation.diff import generate_diff

            patch = generate_diff(
                original,
                current
            )

            # Store the generated patch on disk.
            os.makedirs(
                "reports/patches",
                exist_ok=True
            )

            patch_name = (
                os.path.basename(file_path)
                + ".patch"
            )

            patch_path = os.path.abspath(
                os.path.join(
                    "reports",
                    "patches",
                    patch_name
                )
            )

            with open(patch_path, "w") as patch_file:
                patch_file.write(patch)

            # Create a reversible backup immediately before
            # modifying the source file.
            backup_path = (
                file_path
                + ".purpleguard.bak"
            )

            shutil.copy2(
                file_path,
                backup_path
            )

            # Apply the combined transformation.
            with open(file_path, "w") as file:
                file.write(current)

            results.append({
                "file": file_path,
                "status": "APPLIED",
                "findings": [
                    finding.get("id")
                    for finding in file_findings
                ],
                "backup": backup_path,
                "patch_file": patch_path,
                "original_source": original,
                "updated_source": current,
                "patch": patch
            })

        return {
            "status": "APPLIED",
            "results": results
        }


    def rollback(self, file_path):
        """
        Restore a source file from its PurpleGuard backup.

        The backup is preserved after restoration so the operation
        remains reversible.
        """

        file_path = os.path.abspath(file_path)
        backup_path = file_path + ".purpleguard.bak"

        if not os.path.exists(backup_path):
            return {
                "status": "BACKUP_NOT_FOUND",
                "file": file_path,
                "message": (
                    "No PurpleGuard backup exists for this file."
                )
            }

        shutil.copy2(
            backup_path,
            file_path
        )

        return {
            "status": "ROLLED_BACK",
            "file": file_path,
            "backup": backup_path,
            "message": (
                "Original source restored from "
                "PurpleGuard backup."
            )
        }

    def propose(self, finding):
        patch = self.patcher.create_patch(finding)

        if patch["status"] != "READY":
            return {
                "status": "NO_FIX",
                "finding": finding,
                "patch": patch
            }

        return {
            "status": "PROPOSED",
            "finding": finding,
            "patch": patch,
            "approval_required": True
        }

    def apply(self, finding, approved=False):

        if not approved:
            return {
                "status": "REJECTED",
                "message": (
                    "Fix was not applied because "
                    "user approval was not provided."
                )
            }

        file_path = finding["file"]

        if not os.path.exists(file_path):
            return {
                "status": "FAILED",
                "message": f"File does not exist: {file_path}"
            }

        # Create a backup before modifying the source.
        backup_path = file_path + ".purpleguard.bak"
        shutil.copy2(file_path, backup_path)

        # Generate the patch.
        patch_result = self.patcher.create_patch(finding)

        if patch_result["status"] != "READY":
            return {
                "status": "FAILED",
                "message": (
                    "PurpleGuard AI could not generate "
                    "a safe patch."
                ),
                "backup": backup_path
            }

        # Read the original source.
        with open(file_path, "r") as file:
            original = file.read()

        # Generate the fixed source.
        fixed = self.patcher._generate_actual_fix(
            finding,
            original
        )

        if fixed is None:
            return {
                "status": "FAILED",
                "message": "Fix could not be applied.",
                "backup": backup_path
            }

        # Write the fixed source.
        with open(file_path, "w") as file:
            file.write(fixed)

        # Re-scan the project to verify the vulnerability.
        scanner = SecurityScanner(self.project_path)

        verification = self.verifier.verify_security_fix(
            scanner,
            finding
        )

        if verification["fixed"]:
            return {
                "status": "VERIFIED",
                "file": file_path,
                "backup": backup_path,
                "patch": patch_result["patch"],
                "verification": verification,
                "message": (
                    "Fix applied and vulnerability "
                    "verified as resolved."
                )
            }

        return {
            "status": "APPLIED_NOT_VERIFIED",
            "file": file_path,
            "backup": backup_path,
            "patch": patch_result["patch"],
            "verification": verification,
            "message": (
                "Fix was applied, but PurpleGuard could not "
                "verify that the vulnerability was removed."
            )
        }

    def explain(self, finding, patch_result):
        return {
            "vulnerability": finding.get(
                "name",
                finding.get("id")
            ),
            "severity": finding.get("severity"),
            "file": finding.get("file"),
            "line": finding.get("line"),
            "what_was_fixed": patch_result.get("message"),
            "how_it_was_fixed": patch_result.get("patch"),
            "security_benefit": finding.get(
                "recommendation",
                "The remediation reduces the "
                "identified security risk."
            )
        }
