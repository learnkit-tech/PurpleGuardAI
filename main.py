import argparse
import json
from datetime import datetime

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
        print(
            "No files were modified."
        )
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

    print(
        "Fixed:",
        result["fixed"]
    )

    print(
        "Remaining:",
        result["remaining"]
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


parser = argparse.ArgumentParser(
    description="PurpleGuardAI Security Scanner"
)

subparsers = parser.add_subparsers(
    dest="command"
)

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

else:
    parser.print_help()
