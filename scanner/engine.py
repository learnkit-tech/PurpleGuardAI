import os

from scanner.rules.registry import RULES


class SecurityScanner:

    def __init__(self, path):
        self.path = path
        self.findings = []

        self.ignore_dirs = {
            ".git",
            "__pycache__",
            "venv",
            "env",
            "reports"
        }

    def scan(self):
        # Reset findings so the same scanner instance can safely
        # be reused for multiple scans.
        self.findings = []

        for root, dirs, files in os.walk(self.path):

            dirs[:] = [
                d for d in dirs
                if d not in self.ignore_dirs
            ]

            for file in files:

                if file.endswith(".py"):

                    self.scan_python_file(
                        os.path.join(root, file)
                    )

        return self.findings

    def scan_python_file(self, filepath):

        with open(filepath, "r", errors="ignore") as f:
            lines = f.readlines()

        for rule in RULES:

            rule_findings = rule.check(
                filepath,
                lines
            )

            for finding in rule_findings:

                # Attach rule metadata centrally.
                finding.setdefault(
                    "id",
                    rule.id
                )

                finding.setdefault(
                    "name",
                    rule.name
                )

                finding.setdefault(
                    "severity",
                    rule.severity
                )

                finding.setdefault(
                    "category",
                    rule.category
                )

                finding.setdefault(
                    "file",
                    filepath
                )

                self.findings.append(finding)
