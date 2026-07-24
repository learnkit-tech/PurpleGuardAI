from dev_agent.code_schema import parse_code_response


class CodeGenerator:

    def generate(self, task, ai_response):

        print("\nGenerating code changes...")


        result = parse_code_response(
            ai_response
        )


        if result["status"] == "success":

            return {
                "status": "ready",
                "files": result["files"]
            }


        task_lower = task.lower()


        if "dashboard" in task_lower:

            return {
                "status": "ready",
                "files": [
                    "dashboard/app.py",
                    "dashboard/templates/index.html"
                ]
            }


        if "api" in task_lower:

            return {
                "status": "ready",
                "files": [
                    "api/server.py"
                ]
            }


        if "vulnerability" in task_lower or "rules" in task_lower:

            return {
                "status": "ready",
                "files": [
                    "scanner/rules/"
                ]
            }


        if "sarif" in task_lower:

            return {
                "status": "ready",
                "files": [
                    "scanner/reporting/sarif.py"
                ]
            }


        return {
            "status": "failed",
            "files": [],
            "message": "No matching implementation route found."
        }
