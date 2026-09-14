class VerificationEngine:
    """
    Verifies that a PurpleGuard remediation actually removed
    the vulnerability from the project.
    """

    def run_tests(self, project_path):
        import subprocess

        try:
            result = subprocess.run(
                ["pytest"],
                cwd=project_path,
                capture_output=True,
                text=True,
                timeout=120
            )

            return {
                "tests_passed": result.returncode == 0,
                "output": result.stdout,
                "errors": result.stderr
            }

        except Exception as error:
            return {
                "tests_passed": False,
                "error": str(error)
            }

    def verify_security_fix(self, scanner, previous_finding):
        """
        Re-run PurpleGuard after a remediation and determine whether
        the original vulnerability still exists.
        """

        new_results = scanner.scan()

        previous_id = previous_finding.get("id")
        previous_file = previous_finding.get("file")

        remaining = [
            finding
            for finding in new_results
            if finding.get("id") == previous_id
            and finding.get("file") == previous_file
        ]

        fixed = len(remaining) == 0

        return {
            "fixed": fixed,
            "remaining_issue": not fixed,
            "new_scan_results": new_results,
            "remaining_findings": remaining
        }
