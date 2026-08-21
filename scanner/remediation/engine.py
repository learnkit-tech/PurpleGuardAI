from scanner.remediation.fixes import get_fix
from scanner.remediation.diff import generate_diff


class RemediationEngine:

    def generate_fix(self, finding):

        vulnerability_id = finding["id"]

        fix = get_fix(vulnerability_id)

        patch = generate_diff(
            fix["before"],
            fix["after"]
        )

        return {
            "file": finding["file"],
            "line": finding["line"],
            "vulnerability": finding.get(
                "name",
                fix["title"]
            ),
            "fix_title": fix["title"],
            "before": fix["before"],
            "after": fix["after"],
            "patch": patch
        }
