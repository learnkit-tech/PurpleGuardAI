import os

from .models import HackerReport
from .python_analyzer import analyze_python_file


class PurpleGuardHacker:

    def __init__(self, project_path):

        self.project_path = os.path.abspath(
            os.path.expanduser(project_path)
        )

        self.ignore_dirs = {
            ".git",
            "__pycache__",
            ".venv",
            "venv",
            "env",
            "node_modules",
            "reports",
            ".next",
            "dist",
            "build",
        }

    def hack(self):

        report = HackerReport(
            project=self.project_path
        )

        if not os.path.isdir(self.project_path):

            raise ValueError(
                f"Project does not exist: "
                f"{self.project_path}"
            )

        for root, dirs, files in os.walk(
            self.project_path
        ):

            dirs[:] = [
                directory
                for directory in dirs
                if directory not in self.ignore_dirs
            ]

            for filename in files:

                if not filename.endswith(".py"):
                    continue

                filepath = os.path.join(
                    root,
                    filename
                )

                result = analyze_python_file(
                    filepath
                )

                if result.get("error"):
                    continue

                report.files_analyzed += 1

                report.attack_surfaces.extend(
                    result["sources"]
                )

                report.suspicious_code.extend(
                    result["suspicious"]
                )

                report.attack_paths.extend(
                    result["paths"]
                )

        return report

    def summary(self):

        report = self.hack()

        severity_order = {
            "CRITICAL": 4,
            "HIGH": 3,
            "MEDIUM": 2,
            "LOW": 1,
        }

        report.attack_paths.sort(
            key=lambda path: severity_order.get(
                path.severity,
                0
            ),
            reverse=True,
        )

        return report.to_dict()
