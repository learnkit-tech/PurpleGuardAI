import os

from .findings import ConfirmedFinding
from scanner.remediation.patcher import CodePatcher


CATEGORY_TO_RULE = {
    "CODE_EXECUTION": "PG002",
    "SQL_INJECTION": "PG004",
    "PATH_TRAVERSAL": "PG006",
    "COMMAND_INJECTION": "PG005",
    "XSS": "PG007",
    "OPEN_REDIRECT": "PG008",
}

CATEGORY_LABELS = {
    "CODE_EXECUTION": "Code Injection",
    "SQL_INJECTION": "Injection",
    "PATH_TRAVERSAL": "Path Traversal",
    "COMMAND_INJECTION": "Command Injection",
    "XSS": "Cross-Site Scripting",
    "OPEN_REDIRECT": "Open Redirect",
}


class HackerRemediationAdapter:
    """
    Converts confirmed Hacker findings into PurpleGuard remediation
    findings and produces a non-destructive remediation preview.

    Hacker = proves exploitability.
    CodePatcher = generates the actual fix.
    """

    def __init__(self):
        self.patcher = CodePatcher()

    def adapt(self, finding):
        vulnerability_id = CATEGORY_TO_RULE.get(
            finding.category
        )

        if not vulnerability_id:
            raise ValueError(
                f"No remediation rule mapped for "
                f"{finding.category}"
            )

        return {
            "id": vulnerability_id,
            "name": finding.title,
            "severity": finding.severity,
            "category": CATEGORY_LABELS.get(
                finding.category,
                "Injection"
            ),
            "file": finding.sink_file,
            "line": finding.sink_line,

            "hacker": {
                "finding_id": finding.finding_id,
                "path_id": finding.path_id,
                "category": finding.category,
                "severity": finding.severity,
                "confidence": finding.confidence,

                "source_file": finding.source_file,
                "source_line": finding.source_line,
                "source_name": finding.source_name,

                "sink_file": finding.sink_file,
                "sink_line": finding.sink_line,
                "sink_name": finding.sink_name,

                "validator": finding.validator,
                "payload": finding.payload,
                "evidence": finding.evidence,
                "validated": finding.validated,

                "impact": finding.impact,
            },

            "recommendation": self._recommendation(
                vulnerability_id
            ),

            "code": self._extract_sink_code(finding),
        }

    def adapt_all(self, findings):
        return [
            self.adapt(finding)
            for finding in findings
            if finding.validated
        ]

    def preview_all(self, findings):
        """
        Generate non-destructive remediation previews.

        Nothing is written to the project source files.
        The existing CodePatcher only generates a patch.
        """

        previews = []

        for finding in findings:
            adapted = self.adapt(finding)

            preview = self.patcher.create_patch(
                adapted
            )

            source = self._read_source(
                adapted["file"]
            )

            original_code = adapted.get(
                "code",
                ""
            )

            proposed_code = self._extract_proposed_code(
                preview.get("patch", ""),
                original_code
            )

            previews.append({
                "finding_id": adapted["hacker"]["finding_id"],
                "path_id": adapted["hacker"]["path_id"],
                "rule_id": adapted["id"],
                "category": adapted["hacker"]["category"],
                "severity": adapted["severity"],

                "file": adapted["file"],
                "line": adapted["line"],

                "vulnerable_code": original_code,
                "proposed_code": proposed_code,

                "recommendation": adapted[
                    "recommendation"
                ],

                "explanation": self._explanation(
                    adapted["id"]
                ),

                "patch": preview.get(
                    "patch",
                    ""
                ),

                "patch_file": preview.get(
                    "patch_file"
                ),

                "status": preview.get(
                    "status",
                    "NO_PATCH"
                ),

                "source_available": source is not None,
            })

        return previews

    @staticmethod
    def _read_source(filepath):
        try:
            with open(
                filepath,
                "r",
                encoding="utf-8",
                errors="ignore",
            ) as file:
                return file.read()
        except OSError:
            return None

    @staticmethod
    def _extract_proposed_code(
        patch,
        original_code
    ):
        """
        Extract the proposed replacement for the vulnerable code.

        Ignore added imports and return the replacement corresponding
        to the original vulnerable expression whenever possible.
        """

        if not patch:
            return ""

        additions = []

        for line in patch.splitlines():
            if (
                line.startswith("+")
                and not line.startswith("+++")
            ):
                additions.append(line[1:].strip())

        if not additions:
            return ""

        # Prefer a replacement that resembles the vulnerable line.
        original_tokens = set(
            original_code.replace("(", " ")
            .replace(")", " ")
            .replace("{", " ")
            .replace("}", " ")
            .replace('"', " ")
            .replace("'", " ")
            .split()
        )

        best = additions[0]
        best_score = -1

        for candidate in additions:
            candidate_tokens = set(
                candidate.replace("(", " ")
                .replace(")", " ")
                .replace("{", " ")
                .replace("}", " ")
                .replace('"', " ")
                .replace("'", " ")
                .split()
            )

            score = len(
                original_tokens & candidate_tokens
            )

            # Imports are supporting changes, not the replacement.
            if candidate.startswith("import "):
                score -= 100

            if score > best_score:
                best = candidate
                best_score = score

        return best

    @staticmethod
    def _extract_sink_code(finding):
        filepath = finding.sink_file
        line_number = finding.sink_line

        try:
            with open(
                filepath,
                "r",
                encoding="utf-8",
                errors="ignore",
            ) as file:
                lines = file.readlines()

            if 0 < line_number <= len(lines):
                return lines[line_number - 1].strip()

        except OSError:
            pass

        return finding.sink_name

    @staticmethod
    def _recommendation(vulnerability_id):
        recommendations = {
            "PG002":
                "Replace eval() with safe parsing such as ast.literal_eval().",

            "PG004":
                "Use parameterized queries or prepared statements "
                "so attacker-controlled input cannot alter SQL structure.",

            "PG005":
                "Invoke subprocesses with an argument list and "
                "shell=False, quoting any argument that must pass "
                "through a shell.",

            "PG006":
                "Resolve the target path and verify it stays within "
                "the intended base directory before opening it; "
                "reject any path that escapes it.",

            "PG007":
                "Escape attacker-controlled content with "
                "markupsafe.escape() before including it in a "
                "response body.",

            "PG008":
                "Only allow redirects to relative destinations; "
                "reject any target that starts with a scheme or "
                "protocol-relative slashes.",
        }

        return recommendations.get(
            vulnerability_id,
            "Review and remediate the confirmed vulnerability."
        )

    @staticmethod
    def _explanation(vulnerability_id):
        explanations = {
            "PG002":
                "eval() interprets attacker-controlled input as "
                "Python code. The proposed fix replaces it with "
                "ast.literal_eval(), which only permits safe Python "
                "literal structures.",

            "PG004":
                "The attacker-controlled username reaches the SQL "
                "statement through string construction. The proposed "
                "fix separates SQL structure from user input by using "
                "a parameterized query and passing username as a parameter.",

            "PG005":
                "Attacker-controlled text reaches a shell command line. "
                "The proposed fix passes the command as an argument "
                "list with shell=False so input can never alter "
                "command structure.",

            "PG006":
                "Attacker-controlled input reaches a file path "
                "operation without being confined to an allowed "
                "directory. The proposed fix resolves the final path "
                "and rejects it if it escapes the intended base "
                "directory, preventing access to files outside it.",

            "PG007":
                "Attacker-controlled input is placed into the response "
                "body without escaping. The proposed fix applies "
                "markupsafe.escape() so the content is rendered as "
                "text instead of executable markup.",

            "PG008":
                "Attacker-controlled input chooses the redirect "
                "destination. The proposed fix allows only relative "
                "destinations and rejects anything that looks like an "
                "absolute URL or protocol-relative target.",
        }

        return explanations.get(
            vulnerability_id,
            "PurpleGuard generated this remediation from the "
            "confirmed vulnerability."
        )
