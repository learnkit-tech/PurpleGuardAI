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

         if not os.path.exists(file_path):
             results.append({
                 "file": file_path,
                 "status": "FILE_NOT_FOUND"
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
                 "status": "FAILED"
             })
             continue

         if current == original:
             results.append({
                 "file": file_path,
                 "status": "NO_CHANGE"
             })
             continue

         backup_path = file_path + ".purpleguard.bak"
         shutil.copy2(file_path, backup_path)

         with open(file_path, "w") as file:
             file.write(current)

         results.append({
             "file": file_path,
             "status": "APPLIED",
             "backup": backup_path,
             "findings": [
                 finding.get("id")
                 for finding in file_findings
             ]
         })

     return {
         "status": "APPLIED",
         "results": results
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
