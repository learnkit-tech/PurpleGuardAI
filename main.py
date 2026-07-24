from scanner.reporting.html_report import generate_html_report
from scanner.engine import SecurityScanner
from scanner.reporting import enrich_findings
import json
import argparse
from datetime import datetime


def run_scan(target, generate_json=True, generate_html=True):

    scanner = SecurityScanner(target)

    results = scanner.scan()

    results = enrich_findings(results)

    report = {
        "scanner": "PurpleGuardAI",
        "version": "0.1",
        "timestamp": str(datetime.now()),
        "target": target,
        "findings": results
    }

    print("\nPurpleGuardAI Security Report")
    print("----------------------------")

    if not results:
        print("No vulnerabilities found.")

    for item in results:
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

args = parser.parse_args()

run_scan(
    args.target,
    generate_json=args.json or not (args.json or args.html),
    generate_html=args.html or not (args.json or args.html)
)
