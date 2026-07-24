from dev_agent.code_schema import parse_code_response


class CodeGenerator:

    def generate(self, task, ai_response):

        print("\nGenerating code changes...")


        result = parse_code_response(
            ai_response
        )


        if result["status"] != "success":

            return {
                "status": "failed",
                "files": [],
                "message": result["message"]
            }


        return {
            "status": "ready",
            "files": result["files"]
        }
