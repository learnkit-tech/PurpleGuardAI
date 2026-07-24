from scanner.engine import SecurityScanner
import json
import argparse
from datetime import datetime


def run_scan(target):

    scanner = SecurityScanner(target)

    results = scanner.scan()

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


parser = argparse.ArgumentParser(
    description="PurpleGuardAI Security Scanner"
)

parser.add_argument(
    "target",
    help="Directory to scan"
)

args = parser.parse_args()

run_scan(args.target)
