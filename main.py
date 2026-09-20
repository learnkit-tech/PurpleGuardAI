import argparse
import json
from datetime import datetime

from hacker.orchestrator import PurpleGuardSecurityOrchestrator
from scanner.decision.engine import SecurityDecisionEngine
from scanner.engine import SecurityScanner
from scanner.reporting import generate_report
from scanner.reporting.html_report import generate_html_report
from scanner.filtering import filter_by_severity
from scanner.patches.summary import generate_patch_summary
from scanner.remediation.patcher import CodePatcher
from scanner.developer.session import DeveloperSession


def run_scan(
    target,
    generate_json=True,
    generate_html=True,
    severity=None
):
    scanner = SecurityScanner(target)

    results = scanner.scan()
    report = generate_report(results)

    decision_engine = SecurityDecisionEngine()

    decision = decision_engine.decide(report)

    report["decision"] = decision

    if severity:
        report["findings"] = filter_by_severity(
            report["findings"],
            severity
        )

    patcher = CodePatcher()

    patch_results = patcher.create_patches(
        report["findings"]
    )

    for finding, patch_result in zip(
        report["findings"],
        patch_results
    ):
        finding["patch"] = patch_result

    report.update({
        "scanner": "PurpleGuardAI",
        "version": "0.1",
        "timestamp": str(datetime.now()),
        "target": target
    })

    print("\n🛡️ PurpleGuardAI Security Report")
    print("===============================")

    analysis = report["analysis"]

    print("\nRisk Assessment")
    print("---------------")
    print("Risk Score:", analysis["risk_score"])
    print("Overall Risk:", analysis["overall_risk"])

    print("\nSecurity Decision")
    print("-----------------")
    print("Risk:", decision["risk"])
    print("Action:", decision["action"])
    print(
        "Approval Required:",
        decision["approval_required"]
    )
    print(
        "Verification Required:",
        decision["verification_required"]
    )
    print(
        "Rollback Available:",
        decision["rollback_available"]
    )

    print("\nFindings")
    print("--------")

    if not report["findings"]:
        print("✓ No vulnerabilities detected.")
    else:
        for finding in report["findings"]:
            print(
                f'{finding["id"]} | '
                f'{finding["severity"]} | '
                f'{finding["name"]} | '
                f'{finding["file"]}:'
                f'{finding["line"]}'
            )

    if generate_json:
        with open(
            "reports/scan_report.json",
            "w"
        ) as file:
            json.dump(
                report,
                file,
                indent=4
            )

        print(
            "\nReport saved: "
            "reports/scan_report.json"
        )

    if generate_html:
        generate_html_report(
            "reports/scan_report.json",
            "reports/scan_report.html"
        )

        print(
            "Report saved: "
            "reports/scan_report.html"
        )

    print("\nPatch Summary")
    print("-------------")
    print(generate_patch_summary())

    return report


def run_secure(target, approved=False):
    print("\n🛡️ PurpleGuardAI Remediation")
    print("============================")

    session = DeveloperSession(target)

    before = session.scan()

    findings = before.get(
        "findings",
        []
    )

    print(
        f"\nDetected: {len(findings)} "
        "vulnerability finding(s)"
    )

    if not findings:
        print("\n✓ Project is already secure.")
        return

    for finding in findings:
        print(
            f'- {finding["id"]}: '
            f'{finding["name"]} '
            f'({finding["severity"]})'
        )

    if not approved:
        print("\n⚠️ Approval required.")
        print("No files were modified.")
        print(
            "Run again with "
            "--approve to apply remediation."
        )
        return

    print("\nApplying approved remediation...")

    result = session.secure_all(
        approved=True
    )

    print("\nRemediation Result")
    print("------------------")
    print("Status:", result["status"])

    print("\nFixed")

    for finding in findings:
        finding_id = finding["id"]

        if finding_id in result["fixed"]:
            print(
                f'✓ {finding_id}  '
                f'{finding["name"]}'
            )

    if result["remaining"]:
        print("\nRemaining")

        for finding_id in result["remaining"]:
            print(
                f'⚠️ {finding_id}'
            )

    print("\nVerification")

    if result["status"] == "SECURE":
        print(
            "✓ No vulnerabilities "
            "remain."
        )
        print("\nSTATUS: SECURE")
    else:
        print(
            "⚠️ Some vulnerabilities "
            "remain."
        )
        print("\nSTATUS: PARTIALLY SECURED")

    return result


def run_review(target):
    print("\n🛡️ PurpleGuardAI Review Queue")
    print("=============================")

    session = DeveloperSession(target)

    report = session.scan()
    findings = report.get("findings", [])

    if not findings:
        print("\n✓ No vulnerabilities detected.")
        return

    patcher = CodePatcher()

    auto_fixable = []
    requires_review = []

    for finding in findings:
        if patcher.can_auto_fix(finding):
            auto_fixable.append(finding)
        else:
            requires_review.append(finding)

    print(
        f"\nDetected: {len(findings)} finding(s) "
        f"({len(auto_fixable)} auto-fixable, "
        f"{len(requires_review)} requiring review)\n"
    )

    if auto_fixable:
        print(
            "Auto-fixable "
            "(run: python main.py secure "
            f"{target} --approve)"
        )

        for finding in auto_fixable:
            print(
                f"  ✓ [{finding['id']}] "
                f"{finding.get('name')} "
                f"({finding.get('severity')})"
            )
            print(
                f"    {finding.get('file')}"
                f":{finding.get('line')}"
            )
            print(
                f"    {finding.get('code')}"
            )

        print()

    if requires_review:
        print(
            "Requires manual review "
            "(no safe automated fix):"
        )

        for finding in requires_review:
            print(
                f"  ⚠️ [{finding['id']}] "
                f"{finding.get('name')} "
                f"({finding.get('severity')})"
            )
            print(
                f"    {finding.get('file')}"
                f":{finding.get('line')}"
            )

            code = finding.get("code")

            if code:
                print(
                    f"    {code}"
                )

            print(
                f"    {finding.get('recommendation')}"
            )

        print()
    else:
        print(
            "✓ No findings require "
            "manual review."
        )


def run_hack(target, approved=False):
    """
    Full adversarial pipeline in one command:

    Discover -> Plan -> Validate -> Findings -> Propose
        -> Approve -> Remediate -> Static Rescan -> Tests
        -> Re-attack -> Final Verdict

    Nothing is modified without --approve. Findings without a
    provably safe automated fix are surfaced for manual review and
    never silently rewritten.
    """

    print("\n🛡️ PurpleGuardAI Hack Pipeline")
    print("==============================")
    print(f"Target: {target}")
    print("Mode: AUTHORIZED LOCAL VALIDATION")
    print(f"Approval: {'GRANTED' if approved else 'REQUIRED'}")

    orchestrator = PurpleGuardSecurityOrchestrator(target)

    result = orchestrator.run(approved=approved)

    recon = result.get("recon")

    if recon:
        print("\n[1] Recon")
        print("----")
        print("Files analyzed:", recon["files_analyzed"])
        print("Attack surfaces:", recon["attack_surfaces"])
        print("Attack paths:", recon["attack_paths"])

    plans = result.get("plans")

    if plans:
        print("\n[2] Planned validations")
        print("-----------------------")

        for plan in plans:
            print(
                f"{plan['path_id']} | "
                f"{plan['category']} | "
                f"{plan['severity']} | "
                f"{plan['validator']}"
            )

    validations = result.get("validation")

    if validations:
        print("\n[3] Dynamic validation")
        print("----------------------")

        for validation in validations:
            if validation.get("validated"):
                print(
                    f"[CONFIRMED] {validation['path_id']} "
                    f"{validation['category']}"
                )
            else:
                print(
                    f"[NOT CONFIRMED] "
                    f"{validation.get('path_id')} "
                    f"{validation.get('category')}"
                )

    confirmed = result.get("confirmed_attacks")

    if confirmed is not None:
        print(f"\nConfirmed attacks: {confirmed}")

    remediation = result.get("remediation")

    if remediation:
        requires_review = remediation.get(
            "requires_review",
            [],
        )

        print("\n[4] Remediation proposal")
        print("------------------------")
        print(
            "Auto-fixable (proposed):",
            remediation.get("available", 0),
        )
        print(
            "Requires manual review:",
            len(requires_review),
        )

        for item in requires_review:
            print(
                f"  ⚠️ [{item['rule_id']}] "
                f"{item['category']} "
                f"{item['file']}:{item['line']}"
            )
            print(
                f"     {item.get('recommendation')}"
            )

    if result.get("status") == "APPROVAL_REQUIRED":
        print("\nStatus: APPROVAL_REQUIRED")
        print("\n" + result.get("message", ""))
        print(
            "No files were modified. Re-run with "
            "--approve to apply the proposed remediation."
        )

    elif result.get("status") in (
        "NO_ATTACK_PATHS",
        "NO_VALIDATIONS",
        "NO_CONFIRMED_ATTACKS",
    ):
        print(f"\nStatus: {result['status']}")
        print("\n" + result.get("message", ""))

    elif result.get("status") == "REMEDIATION_FAILED":
        print(f"\nStatus: {result['status']}")
        print("\n" + result.get("message", ""))

        remediation_result = (
            remediation or {}
        ).get("result", {})

        for item in remediation_result.get(
            "results",
            [],
        ):
            print(
                f"  ✗ {item.get('status')} "
                f"{item.get('file')} "
                f"{item.get('findings', [])}"
            )

    else:
        remediation_result = (
            remediation or {}
        ).get("result", {})

        print("\n[5] Remediation applied")
        print("-----------------------")

        for item in remediation_result.get(
            "results",
            [],
        ):
            if item.get("status") == "APPLIED":
                print(
                    f"✓ {item['file']}: "
                    f"{', '.join(item.get('findings', []))}"
                )
                print(f"    backup: {item.get('backup')}")
                print(f"    patch: {item.get('patch_file')}")
            else:
                print(
                    f"✗ {item.get('status')} "
                    f"{item.get('file')} "
                    f"{item.get('findings', [])}"
                )

        verification = result.get("verification", {})

        static_scan = verification.get(
            "static_scan",
            {},
        )

        remaining = static_scan.get(
            "remaining_original_findings",
            [],
        )

        print("\n[6] Verification")
        print("----------------")
        print(
            "Static rescan:",
            "PASS"
            if static_scan.get("passed")
            else f"FAIL ({len(remaining)} original finding(s) remain)",
        )

        for finding in remaining:
            print(
                f"    remaining: {finding.get('id')} "
                f"{finding.get('file')}"
            )

        tests = verification.get("tests", {})

        print(
            "Tests:",
            "PASS"
            if tests.get("passed")
            else "FAIL",
        )

        hacker = verification.get("hacker", {})

        hacker_results = hacker.get("results", [])

        blocked = [
            item
            for item in hacker_results
            if item.get("blocked")
        ]

        print(
            f"Re-attack: {len(blocked)}/"
            f"{len(hacker_results)} attacks blocked"
        )

        for item in hacker_results:
            if item.get("blocked"):
                print(
                    f"    [BLOCKED] {item.get('path_id')} "
                    f"{item.get('category')}"
                )
            else:
                print(
                    f"    [STILL WORKS] "
                    f"{item.get('path_id')} "
                    f"{item.get('category')}"
                )

        verdict = verification.get("verdict", {})

        print(
            f"\nFINAL VERDICT: "
            f"{verdict.get('status')}"
        )
        print(
            f"  static scan: "
            f"{'PASS' if verdict.get('static_scan_passed') else 'FAIL'}"
        )
        print(
            f"  tests: "
            f"{'PASS' if verdict.get('tests_passed') else 'FAIL'}"
        )
        print(
            f"  hacker re-attack: "
            f"{'PASS' if verdict.get('hacker_verification_passed') else 'FAIL'}"
        )

        if result.get("status") == "SECURITY_VERIFIED":
            print("\n" + result.get("message", ""))
        else:
            print(
                "\n⚠️ "
                "Security is NOT fully verified. Findings that "
                "require manual review remain exploitable until "
                "they are fixed by hand."
            )

    report_path = "reports/orchestrator_report.json"

    import os

    os.makedirs("reports", exist_ok=True)

    with open(report_path, "w") as file:
        json.dump(result, file, indent=4)

    print(f"\nReport saved: {report_path}")

    return result


def run_rollback(target):
    print("\n🛡️ PurpleGuardAI Rollback")
    print("=========================")

    session = DeveloperSession(target)

    print(
        f"\nRestoring: {target}"
    )

    result = session.remediation.rollback(
        target
    )

    if result["status"] == "ROLLED_BACK":
        print("\n✓ Original source restored.")
        print("✓ Backup preserved.")
        print("\nSTATUS: ROLLED BACK")
    else:
        print("\n⚠️ Rollback failed.")
        print(
            result.get(
                "message",
                "Backup not found."
            )
        )

    return result


parser = argparse.ArgumentParser(
    description="PurpleGuardAI Security Scanner"
)

subparsers = parser.add_subparsers(
    dest="command"
)


# -------------------------
# SCAN COMMAND
# -------------------------

scan_parser = subparsers.add_parser(
    "scan",
    help="Scan a project"
)

scan_parser.add_argument(
    "target",
    help="Directory to scan"
)

scan_parser.add_argument(
    "--json",
    action="store_true",
    help="Generate JSON report"
)

scan_parser.add_argument(
    "--html",
    action="store_true",
    help="Generate HTML report"
)

scan_parser.add_argument(
    "--severity",
    help="Filter findings by minimum severity"
)


# -------------------------
# SECURE COMMAND
# -------------------------

secure_parser = subparsers.add_parser(
    "secure",
    help="Scan and remediate a project"
)

secure_parser.add_argument(
    "target",
    help="Directory to secure"
)

secure_parser.add_argument(
    "--approve",
    action="store_true",
    help="Approve remediation and modify files"
)


# -------------------------
# ROLLBACK COMMAND
# -------------------------

rollback_parser = subparsers.add_parser(
    "rollback",
    help="Restore a file from its PurpleGuard backup"
)

rollback_parser.add_argument(
    "target",
    help="File to restore"
)


# -------------------------
# REVIEW COMMAND
# -------------------------

review_parser = subparsers.add_parser(
    "review",
    help=(
        "Show which findings are auto-fixable "
        "and which need manual review"
    )
)

review_parser.add_argument(
    "target",
    help="Directory to review"
)


# -------------------------
# HACK COMMAND
# -------------------------

hack_parser = subparsers.add_parser(
    "hack",
    help=(
        "Run the full adversarial pipeline: discover, validate, "
        "propose, remediate (with --approve), and re-verify"
    )
)

hack_parser.add_argument(
    "target",
    help="Authorized local target directory"
)

hack_parser.add_argument(
    "--approve",
    action="store_true",
    help=(
        "Approve remediation of confirmed auto-fixable "
        "findings"
    )
)


# -------------------------
# COMMAND DISPATCH
# -------------------------

args = parser.parse_args()


if args.command == "scan":

    run_scan(
        args.target,
        generate_json=(
            args.json
            or not (args.json or args.html)
        ),
        generate_html=(
            args.html
            or not (args.json or args.html)
        ),
        severity=args.severity
    )

elif args.command == "secure":

    run_secure(
        args.target,
        approved=args.approve
    )

elif args.command == "rollback":

    run_rollback(
        args.target
    )

elif args.command == "review":

    run_review(
        args.target
    )

elif args.command == "hack":

    run_hack(
        args.target,
        approved=args.approve
    )

else:
    parser.print_help()
