from dataclasses import dataclass, asdict


@dataclass
class ConfirmedFinding:
    finding_id: str
    path_id: str
    category: str
    severity: str
    confidence: float

    title: str

    source_file: str
    source_line: int
    source_name: str

    sink_file: str
    sink_line: int
    sink_name: str

    validator: str
    payload: str

    evidence: str
    validated: bool

    impact: str

    def to_dict(self):
        return asdict(self)


class FindingBuilder:

    TITLES = {
        "CODE_EXECUTION":
            "Attacker-controlled input reaches dynamic code execution.",

        "SQL_INJECTION":
            "Attacker-controlled input reaches a dynamic SQL query.",

        "COMMAND_INJECTION":
            "Attacker-controlled input reaches shell command execution.",

        "XSS":
            "Attacker-controlled input is reflected into an HTTP response without escaping.",

        "OPEN_REDIRECT":
            "Attacker-controlled input controls a redirect destination.",

        "SSRF":
            "Attacker-controlled input controls an outbound request destination.",
    }

    IMPACTS = {
        "CODE_EXECUTION":
            "An attacker may be able to influence application code execution.",

        "SQL_INJECTION":
            "An attacker may be able to manipulate database queries and access or alter database data.",

        "COMMAND_INJECTION":
            "An attacker may be able to execute arbitrary operating-system commands on the host.",

        "XSS":
            "An attacker may be able to run script in a victim's browser, enabling session theft or defacement.",

        "OPEN_REDIRECT":
            "An attacker may be able to redirect users to attacker-chosen destinations for phishing.",

        "SSRF":
            "An attacker may be able to reach internal services, cloud metadata endpoints, or arbitrary hosts through the server.",
    }

    def build(self, attack_paths, plans, validations):

        path_map = {
            path["id"]: path
            for path in attack_paths
        }

        plan_map = {
            plan["path_id"]: plan
            for plan in plans
        }

        validation_map = {
            result["path_id"]: result
            for result in validations
        }

        findings = []

        for path_id, path in path_map.items():

            plan = plan_map.get(path_id)

            validation = validation_map.get(
                path_id
            )

            if not plan or not validation:
                continue

            nodes = path.get("nodes", [])

            source = next(
                (
                    node
                    for node in nodes
                    if node.get("kind") == "SOURCE"
                ),
                None,
            )

            sink = next(
                (
                    node
                    for node in nodes
                    if node.get("kind") == "SINK"
                ),
                None,
            )

            if not source or not sink:
                continue

            source_location = source.get(
                "location",
                {}
            )

            sink_location = sink.get(
                "location",
                {}
            )

            finding = ConfirmedFinding(
                finding_id=f"PG-HACK-{path_id}",

                path_id=path_id,

                category=path.get(
                    "category",
                    plan["category"],
                ),

                severity=path.get(
                    "severity",
                    plan["severity"],
                ),

                confidence=path.get(
                    "confidence",
                    plan["confidence"],
                ),

                title=self.TITLES.get(
                    path["category"],
                    "Confirmed security attack path.",
                ),

                source_file=source_location.get(
                    "file",
                    "",
                ),

                source_line=source_location.get(
                    "line",
                    0,
                ),

                source_name=source.get(
                    "name",
                    "",
                ),

                sink_file=sink_location.get(
                    "file",
                    "",
                ),

                sink_line=sink_location.get(
                    "line",
                    0,
                ),

                sink_name=sink.get(
                    "name",
                    "",
                ),

                validator=plan.get(
                    "validator",
                    "",
                ),

                payload=validation.get(
                    "payload",
                    "",
                ),

                evidence=validation.get(
                    "evidence",
                    "",
                ),

                validated=bool(
                    validation.get(
                        "validated",
                        False,
                    )
                ),

                impact=self.IMPACTS.get(
                    path["category"],
                    path.get(
                        "impact",
                        "",
                    ),
                ),
            )

            findings.append(
                finding
            )

        return findings
