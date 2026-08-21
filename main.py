from scanner.patches.summary import generate_patch_summary
from scanner.reporting.html_report import generate_html_report
from scanner.engine import SecurityScanner
from scanner.reporting import generate_report
from scanner.filtering import filter_by_severity
from scanner.remediation.patcher import CodePatcher
import json
import argparse
from datetime import datetime


def run_scan(target, generate_json=True, generate_html=True, severity=None):

    scanner = SecurityScanner(target)

    results = scanner.scan()

    report = generate_report(results)

    if severity:
        report["findings"] = filter_by_severity(
            report["findings"],
            severity
        )

    patcher = CodePatcher()

    for finding in report["findings"]:
        finding["patch"] = patcher.create_patch(finding)

    report.update({
        "scanner": "PurpleGuardAI",
        "version": "0.1",
        "timestamp": str(datetime.now()),
        "target": target
    })

    print("\nPurpleGuardAI Security Report")
    print("----------------------------")

    analysis = report["analysis"]

    print("\nRisk Assessment")
    print("----------------")
    print("Risk Score:", analysis["risk_score"])
    print("Overall Risk:", analysis["overall_risk"])

    print("\nAttack Paths")
    print("-------------")

    for path in analysis["attack_paths"]:
        print("-", path)

    print("\nFindings")
    print("--------")

    for item in report["findings"]:
        print(item)

    if generate_json:
        with open("reports/scan_report.json", "w") as file:
            json.dump(report, file, indent=4)

        print("\nReport saved: reports/scan_report.json")

    if generate_html:
        generate_html_report(
            "reports/scan_report.json",
            "reports/scan_report.html"
        )

    patch_summary = generate_patch_summary()

    print("\nPatch Summary")
    print("-------------")
    print(patch_summary)


parser = argparse.ArgumentParser(
    description="PurpleGuardAI Security Scanner"
)

parser.add_argument(
    "target",
    help="Directory to scan"
)

parser.add_argument(
    "--json",
    action="store_true",
    help="Generate JSON report"
)

parser.add_argument(
    "--html",
    action="store_true",
    help="Generate HTML report"
)

parser.add_argument(
    "--severity",
    help="Filter findings by minimum severity"
)

args = parser.parse_args()


run_scan(
    args.target,
    generate_json=args.json or not (args.json or args.html),
    generate_html=args.html or not (args.json or args.html),
    severity=args.severity
)
