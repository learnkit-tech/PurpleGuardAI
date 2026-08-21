from pathlib import Path

from scanner.engine import SecurityScanner
from scanner.risk import RiskAnalyzer

from scanner.analyzer.language_detector import detect_languages
from scanner.analyzer.framework_detector import detect_framework
from scanner.analyzer.dependency_analyzer import analyze_dependencies
from scanner.analyzer.attack_surface import discover_attack_surface

from scanner.reporting import enrich_findings
from scanner.remediation.workflow import RemediationWorkflow


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

        By default this method never modifies source code because
        approval is required explicitly.
        """

        # Step 1: scan the project.
        report = self.scan()
        findings = report.get("findings", [])

        if not findings:
            return {
                "status": "SECURE",
                "message": "No vulnerabilities were detected.",
                "scan": report
            }

        # Step 2: select a finding.
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
                        item.get("id") for item in findings
                    ],
                    "scan": report
                }
        else:
            # Use the first finding when no ID is supplied.
            finding = findings[0]

        # Step 3: generate a remediation proposal.
        proposal = self.propose_fix(finding)

        if proposal.get("status") != "PROPOSED":
            return {
                "status": "NO_FIX",
                "finding": finding,
                "proposal": proposal,
                "scan": report
            }

        # Step 4: require explicit approval.
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

        # Step 5: apply and verify the approved fix.
        patch_result = self.apply_fix(
            finding,
            approved=True
        )

        # Step 6: explain the result.
        explanation = self.explain_fix(
            finding,
            patch_result
        )

        # Step 7: rescan after the modification.
        rescanned = self.rescan()

        return {
            "status": patch_result.get("status"),
            "finding": finding,
            "proposal": proposal,
            "patch_result": patch_result,
            "explanation": explanation,
            "rescan": rescanned
        }
