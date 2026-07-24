import os
import ast

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
            source = f.read()

        try:
            tree = ast.parse(source)

        except SyntaxError:
            return


        for rule in RULES:

            self.findings.extend(
                rule["function"](tree, filepath)
            )
