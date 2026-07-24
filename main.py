from scanner.reporting.html_report import generate_html_report
from scanner.engine import SecurityScanner
from scanner.reporting import enrich_findings
import json
import argparse
from datetime import datetime


def run_scan(target):

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

    with open("reports/scan_report.json", "w") as file:
        json.dump(report, file, indent=4)

        print("\nReport saved: reports/scan_report.json")

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

args = parser.parse_args()

run_scan(args.target)

