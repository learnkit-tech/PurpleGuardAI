import os

from hacker.engine import PurpleGuardHacker
from hacker.planner import AttackPlanner
from hacker.findings import FindingBuilder
from hacker.remediation_adapter import HackerRemediationAdapter
from hacker.reverification import HackerReverification
from hacker.validation.local_target import LocalTarget

from scanner.engine import SecurityScanner
from scanner.remediation.workflow import RemediationWorkflow
from scanner.verification.engine import VerificationEngine


class PurpleGuardSecurityOrchestrator:
    """
    End-to-end PurpleGuard security workflow.

    Discover
        -> Validate
        -> Propose
        -> Approve
        -> Remediate
        -> Static Rescan
        -> Tests
        -> Re-attack
        -> Final Security Verdict
    """

    def __init__(self, project_path):
        self.project_path = os.path.abspath(
            os.path.expanduser(project_path)
        )

        self.verification_engine = VerificationEngine()

    def discover(self):
        hacker = PurpleGuardHacker(
            self.project_path
        )

        report = hacker.hack()
        report_dict = report.to_dict()

        return report, report_dict

    def plan(self, report_dict):
        planner = AttackPlanner()

        return planner.plan(
            report_dict["attack_paths"]
        )

    def validate(self, report_dict, plans):
        target = LocalTarget(
            self.project_path
        )

        target.start()

        try:
            from hacker.validation.validator import (
                LocalAttackValidator
            )

            validator = LocalAttackValidator(
                target.base_url
            )

            validations = []

            for plan in plans:

                method = getattr(
                    validator,
                    plan.validator,
                    None
                )

                if method is None:

                    validations.append({
                        "path_id": plan.path_id,
                        "category": plan.category,
                        "validated": False,
                        "payload": "",
                        "evidence": (
                            "Validator not found: "
                            f"{plan.validator}"
                        )
                    })

                    continue

                result = method()

                validations.append({
                    "path_id": plan.path_id,
                    "category": plan.category,
                    "severity": plan.severity,
                    "validator": plan.validator,
                    **result,
                })

            return validations

        finally:
            target.stop()

    def build_findings(
        self,
        report_dict,
        plans,
        validations
    ):
        plan_dicts = [
            {
                "path_id": plan.path_id,
                "category": plan.category,
                "severity": plan.severity,
                "confidence": plan.confidence,
                "validator": plan.validator,
            }
            for plan in plans
        ]

        return FindingBuilder().build(
            report_dict["attack_paths"],
            plan_dicts,
            validations,
        )

    def propose(self, findings):
        adapter = HackerRemediationAdapter()

        return adapter.adapt_all(
            findings
        )

    def remediate(
        self,
        remediation_findings,
        approved=False
    ):
        workflow = RemediationWorkflow(
            self.project_path
        )

        return workflow.apply_patches(
            remediation_findings,
            approved=approved
        )

    def reverify(self, findings):
        if not findings:
            return {
                "status": "NOT_VERIFIED",
                "all_attacks_blocked": False,
                "results": [],
                "message": (
                    "No confirmed Hacker findings "
                    "to replay."
                )
            }

        target = LocalTarget(
            self.project_path
        )

        target.start()

        try:

            reverification = HackerReverification(
                target.base_url
            )

            results = reverification.verify(
                findings
            )

            return reverification.verdict(
                results
            )

        finally:
            target.stop()

    def verify_static(self, findings):
        """
        Re-run PurpleGuard's static scanner after remediation.
        """

        scanner = SecurityScanner(
            self.project_path
        )

        previous_findings = []

        for finding in findings:

            if hasattr(
                finding,
                "to_dict"
            ):
                previous_findings.append(
                    self._hacker_to_static_reference(
                        finding
                    )
                )
            else:
                previous_findings.append(
                    finding
                )

        return self.verification_engine.verify_static_scan(
            scanner,
            previous_findings
        )

    @staticmethod
    def _hacker_to_static_reference(
        finding
    ):
        """
        Map a confirmed Hacker finding to the corresponding
        PurpleGuard static rule.
        """

        category_to_rule = {
            "CODE_EXECUTION": "PG002",
            "SQL_INJECTION": "PG004",
        }

        return {
            "id": category_to_rule.get(
                finding.category
            ),
            "file": finding.sink_file,
        }

    def verify_tests(self):
        """
        Run the project's automated tests after remediation.
        """

        return self.verification_engine.verify_tests(
            self.project_path
        )

    def run(self, approved=False):

        result = {
            "agent": "purpleguard",
            "mode": "secure",
            "project": self.project_path,
        }

        # =================================================
        # 1. DISCOVER
        # =================================================

        report, report_dict = self.discover()

        result["recon"] = {
            "files_analyzed": report.files_analyzed,
            "attack_surfaces": len(
                report.attack_surfaces
            ),
            "attack_paths": len(
                report.attack_paths
            ),
        }

        if not report.attack_paths:

            result["status"] = (
                "NO_ATTACK_PATHS"
            )

            result["message"] = (
                "No attack paths were discovered."
            )

            return result

        # =================================================
        # 2. PLAN
        # =================================================

        plans = self.plan(
            report_dict
        )

        result["plans"] = [
            {
                "path_id": plan.path_id,
                "category": plan.category,
                "severity": plan.severity,
                "confidence": plan.confidence,
                "validator": plan.validator,
            }
            for plan in plans
        ]

        if not plans:

            result["status"] = (
                "NO_VALIDATIONS"
            )

            result["message"] = (
                "Attack paths were found, but "
                "no validators are registered."
            )

            return result

        # =================================================
        # 3. VALIDATE
        # =================================================

        validations = self.validate(
            report_dict,
            plans
        )

        confirmed = [
            validation
            for validation in validations
            if validation.get(
                "validated"
            ) is True
        ]

        result["validation"] = validations

        result["confirmed_attacks"] = len(
            confirmed
        )

        if not confirmed:

            result["status"] = (
                "NO_CONFIRMED_ATTACKS"
            )

            result["message"] = (
                "Potential attack paths were discovered, "
                "but none were confirmed."
            )

            return result

        # =================================================
        # 4. BUILD FINDINGS
        # =================================================

        findings = self.build_findings(
            report_dict,
            plans,
            validations
        )

        result["findings"] = [
            finding.to_dict()
            for finding in findings
        ]

        # =================================================
        # 5. PROPOSE REMEDIATION
        # =================================================

        remediation_findings = self.propose(
            findings
        )

        adapter = HackerRemediationAdapter()

        remediation_previews = adapter.preview_all(
            findings
        )

        result["remediation"] = {
            "available": len(
                remediation_findings
            ),
            "approved": approved,
            "previews": remediation_previews,
        }

        if not approved:

            result["status"] = (
                "APPROVAL_REQUIRED"
            )

            result["message"] = (
                "Confirmed vulnerabilities have been "
                "validated and fixes are available. "
                "Re-run with --approve to modify "
                "the project."
            )

            return result

        # =================================================
        # 6. APPLY REMEDIATION
        # =================================================

        remediation_result = self.remediate(
            remediation_findings,
            approved=True
        )

        result["remediation"]["result"] = (
            remediation_result
        )

        failed = any(
            item.get("status") != "APPLIED"
            for item in remediation_result.get(
                "results",
                []
            )
        )

        if failed:

            result["status"] = (
                "REMEDIATION_FAILED"
            )

            result["message"] = (
                "PurpleGuard could not apply "
                "all approved remediation changes."
            )

            return result

        # =================================================
        # 7. STATIC RESCAN
        # =================================================

        static_verification = (
            self.verify_static(
                findings
            )
        )

        result["verification"] = {
            "static_scan": static_verification
        }

        # =================================================
        # 8. TESTS
        # =================================================

        test_verification = (
            self.verify_tests()
        )

        result["verification"]["tests"] = (
            test_verification
        )

        # =================================================
        # 9. RE-ATTACK
        # =================================================

        hacker_verification = (
            self.reverify(
                findings
            )
        )

        result["hacker_verification"] = (
            hacker_verification
        )

        result["verification"]["hacker"] = (
            hacker_verification
        )

        # =================================================
        # 10. FINAL VERDICT
        # =================================================

        final_verdict = (
            self.verification_engine.final_verdict(
                static_verification,
                test_verification,
                hacker_verification,
            )
        )

        result["verification"]["verdict"] = (
            final_verdict
        )

        result["status"] = (
            final_verdict["status"]
        )

        if result["status"] == "SECURITY_VERIFIED":

            result["message"] = (
                "PurpleGuard verified the remediation "
                "through static analysis, automated tests, "
                "and adversarial re-validation."
            )

        else:

            result["message"] = (
                "PurpleGuard could not establish a complete "
                "security verification across all "
                "verification layers."
            )

        return result
