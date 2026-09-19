from pathlib import Path

from scanner.engine import SecurityScanner
from scanner.risk import RiskAnalyzer

from scanner.analyzer.language_detector import detect_languages
from scanner.analyzer.framework_detector import detect_framework
from scanner.analyzer.dependency_analyzer import analyze_dependencies
from scanner.analyzer.attack_surface import discover_attack_surface

from scanner.reporting import enrich_findings
from scanner.remediation.workflow import RemediationWorkflow
from scanner.remediation.patcher import CodePatcher


class DeveloperSession:
    """
    Security workspace for an actively developed project.

    Coordinates analysis, scanning, risk analysis,
    remediation, verification, and rescanning.
    """

    def __init__(self, project_path):
        self.project_path = str(Path(project_path).resolve())

        self.scanner = SecurityScanner(self.project_path)
        self.risk_analyzer = RiskAnalyzer()
        self.remediation = RemediationWorkflow(self.project_path)

        self.last_findings = []
        self.last_report = None

    def analyze(self):
        """Understand the project structure."""
        project_path = Path(self.project_path)

        return {
            "languages": detect_languages(project_path),
            "framework": detect_framework(project_path),
            "dependencies": analyze_dependencies(project_path),
            "attack_surface": discover_attack_surface(project_path)
        }

    def scan(self):
        """Run the PurpleGuard vulnerability scanner."""
        raw_findings = self.scanner.scan()

        findings = enrich_findings(raw_findings)
        analysis = self.risk_analyzer.analyze(findings)

        self.last_findings = findings

        self.last_report = {
            "project": self.project_path,
            "findings": findings,
            "analysis": analysis
        }

        return self.last_report

    def propose_fix(self, finding):
        """Generate a remediation proposal requiring approval."""
        return self.remediation.propose(finding)

    def apply_fix(self, finding, approved=False):
        """Apply an approved remediation and verify it."""
        return self.remediation.apply(
            finding,
            approved=approved
        )

    def explain_fix(self, finding, patch_result):
        """Explain a remediation result."""
        return self.remediation.explain(
            finding,
            patch_result
        )

    def rescan(self):
        """Re-run the security scan after changes."""
        return self.scan()

    def secure(self, finding_id=None, approved=False):
        """
        Run a complete PurpleGuard remediation workflow.

        Workflow:
            scan -> select finding -> propose -> approve/apply
            -> verify -> rescan
        """

        report = self.scan()
        findings = report.get("findings", [])

        if not findings:
            return {
                "status": "SECURE",
                "message": "No vulnerabilities were detected.",
                "scan": report
            }

        finding = None

        if finding_id is not None:
            for item in findings:
                if item.get("id") == finding_id:
                    finding = item
                    break

            if finding is None:
                return {
                    "status": "FINDING_NOT_FOUND",
                    "finding_id": finding_id,
                    "available_findings": [
                        item.get("id")
                        for item in findings
                    ],
                    "scan": report
                }
        else:
            finding = findings[0]

        proposal = self.propose_fix(finding)

        if proposal.get("status") != "PROPOSED":
            return {
                "status": "NO_FIX",
                "finding": finding,
                "proposal": proposal,
                "scan": report
            }

        if not approved:
            return {
                "status": "APPROVAL_REQUIRED",
                "finding": finding,
                "proposal": proposal,
                "message": (
                    "A remediation was proposed but not applied. "
                    "Set approved=True to authorize the change."
                )
            }

        patch_result = self.apply_fix(
            finding,
            approved=True
        )

        explanation = self.explain_fix(
            finding,
            patch_result
        )

        rescanned = self.rescan()

        return {
            "status": patch_result.get("status"),
            "finding": finding,
            "proposal": proposal,
            "patch_result": patch_result,
            "explanation": explanation,
            "rescan": rescanned
        }

    def secure_all(self, approved=False):
        """
        Scan and remediate all detected vulnerabilities.

        Findings are grouped by file so multiple vulnerabilities
        in the same file are applied together.
        """

        report = self.scan()
        findings = report.get("findings", [])

        if not findings:
            return {
                "status": "SECURE",
                "message": "No vulnerabilities were detected.",
                "fixed": [],
                "remaining": []
            }

        if not approved:
            proposals = [
                self.propose_fix(finding)
                for finding in findings
            ]

            return {
                "status": "APPROVAL_REQUIRED",
                "message": (
                    "Remediation proposals generated. "
                    "Set approved=True to apply fixes."
                ),
                "proposals": proposals
            }

        # Only findings with a provably safe automated fix are
        # remediated. Provability is decided per finding (for
        # example, only certain PG006 path-construction shapes can
        # be safely transformed); everything else is surfaced as a
        # finding requiring manual review instead of being
        # silently rewritten.
        patcher = CodePatcher()

        auto_fixable = [
            finding
            for finding in findings
            if patcher.can_auto_fix(finding)
        ]

        requires_review = [
            finding
            for finding in findings
            if not patcher.can_auto_fix(finding)
        ]

        if not auto_fixable:
            return {
                "status": "REVIEW_REQUIRED",
                "message": (
                    "No findings have a safe automated fix. "
                    "Manual review is required."
                ),
                "fixed": [],
                "remaining": [
                    finding.get("id")
                    for finding in requires_review
                ],
                "requires_review": requires_review,
                "final_scan": report
            }

        apply_result = self.remediation.apply_patches(
            auto_fixable,
            approved=True
        )

        final_scan = self.rescan()

        remaining = [
            item.get("id")
            for item in final_scan.get("findings", [])
        ]

        fixed = [
            finding.get("id")
            for finding in auto_fixable
            if finding.get("id") not in remaining
        ]

        review_ids = [
            finding.get("id")
            for finding in requires_review
        ]

        return {
            "status": (
                "SECURE"
                if not remaining
                else "PARTIALLY_SECURED"
            ),
            "fixed": fixed,
            "remaining": remaining,
            "requires_review": requires_review,
            "review_ids": review_ids,
            "results": apply_result.get(
                "results",
                []
            ),
            "final_scan": final_scan
        }
