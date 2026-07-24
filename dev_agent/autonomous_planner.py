import os
import json


class AutonomousPlanner:

    def __init__(self):
        self.task_file = "tasks/roadmap.json"


    def inspect_project(self):

        findings = []

        if not os.path.exists("api"):
            findings.append(
                "Create API interface"
            )

        if not os.path.exists("dashboard"):
            findings.append(
                "Create web dashboard"
            )

        if not os.path.exists(
            "scanner/reporting/sarif.py"
        ):
            findings.append(
                "Add SARIF security report output"
            )

        if not os.path.exists("tests"):
            findings.append(
                "Improve testing system"
            )

        return findings


    def generate_tasks(self):

        discoveries = self.inspect_project()

        tasks = []

        for index, item in enumerate(discoveries):

            tasks.append(
                {
                    "id": index + 1,
                    "task": item,
                    "status": "pending"
                }
            )


        with open(self.task_file, "w") as file:
            json.dump(
                tasks,
                file,
                indent=4
            )


        return tasks

