class PurpleGuardAgent:

    def __init__(self, pipeline):
        self.pipeline = pipeline


    def execute(self, task):
        action = task.get("action")
        project = task.get("project")


        if action == "security_scan":
            return self.pipeline.run(project)


        if action == "analyze":
            return {
                "status": "analysis_requested",
                "project": project
            }


        if action == "fix":
            return {
                "status": "fix_requested",
                "project": project
            }


        return {
            "status": "unknown_task"
        }
