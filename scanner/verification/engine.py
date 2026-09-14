import subprocess


class VerificationEngine:
    """
    PurpleGuard verification engine.

    Verification layers:

        Static Scan
             +
        Automated Tests
             +
        Hacker Re-validation
             =
        Final Security Verdict
    """

    def run_tests(self, project_path):
        """
        Run the project's automated test suite.
        """

        try:
            result = subprocess.run(
                ["pytest"],
                cwd=project_path,
                capture_output=True,
                text=True,
                timeout=120,
            )

            return {
                "tests_passed": result.returncode == 0,
                "return_code": result.returncode,
                "output": result.stdout,
                "errors": result.stderr,
            }

        except Exception as error:
            return {
                "tests_passed": False,
                "return_code": None,
                "output": "",
                "errors": str(error),
            }

    def verify_security_fix(
        self,
        scanner,
        previous_finding
    ):
        """
        Re-run the static scanner and determine whether the
        original vulnerability still exists.
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
            "remaining_findings": remaining,
        }

    def verify_hacker_fix(
        self,
        hacker_finding,
        validation
    ):
        """
        Verify that a previously confirmed Hacker attack
        no longer succeeds.
        """

        previously_validated = bool(
            hacker_finding.get("validated")
        )

        currently_validated = bool(
            validation.get("validated")
        )

        if not previously_validated:
            return {
                "fixed": False,
                "status": "NOT_VERIFIED",
                "message": (
                    "Original Hacker finding was not confirmed, "
                    "so exploit regression cannot be established."
                ),
            }

        fixed = not currently_validated

        return {
            "fixed": fixed,
            "status": (
                "HACK_BLOCKED"
                if fixed
                else "HACK_STILL_WORKS"
            ),
            "previously_validated": previously_validated,
            "currently_validated": currently_validated,
            "payload": validation.get("payload"),
            "evidence": validation.get("evidence"),
        }

    def verify_static_scan(
        self,
        scanner,
        previous_findings
    ):
        """
        Re-run the static scanner after remediation.

        The verification passes only when none of the original
        vulnerability IDs remain in their original files.
        """

        scan_results = scanner.scan()

        remaining = []

        for previous in previous_findings:

            previous_id = previous.get("id")
            previous_file = previous.get("file")

            matches = [
                finding
                for finding in scan_results
                if finding.get("id") == previous_id
                and finding.get("file") == previous_file
            ]

            remaining.extend(matches)

        return {
            "passed": len(remaining) == 0,
            "scan_findings": scan_results,
            "remaining_original_findings": remaining,
            "remaining_count": len(remaining),
        }

    def verify_tests(self, project_path):
        """
        Normalize the test result into the common verification format.
        """

        result = self.run_tests(project_path)

        return {
            "passed": bool(
                result.get("tests_passed")
            ),
            "tests_passed": bool(
                result.get("tests_passed")
            ),
            "return_code": result.get("return_code"),
            "output": result.get("output", ""),
            "errors": result.get("errors", ""),
        }

    def final_verdict(
        self,
        static_scan,
        tests,
        hacker
    ):
        """
        Combine all verification layers into one security verdict.

        PurpleGuard only reports SECURITY_VERIFIED when every
        verification layer passes.
        """

        static_passed = bool(
            static_scan.get("passed")
        )

        tests_passed = bool(
            tests.get("passed")
        )

        hacker_passed = (
            hacker.get("status")
            == "SECURITY_VERIFIED"
        )

        overall = (
            static_passed
            and tests_passed
            and hacker_passed
        )

        return {
            "status": (
                "SECURITY_VERIFIED"
                if overall
                else "SECURITY_NOT_VERIFIED"
            ),
            "static_scan_passed": static_passed,
            "tests_passed": tests_passed,
            "hacker_verification_passed": hacker_passed,
            "all_checks_passed": overall,
        }
