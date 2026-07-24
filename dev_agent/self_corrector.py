from agent_api.tools import run_command


class SelfCorrector:

    def run_tests(self):

        result = run_command(
            "python -m unittest discover -s tests -p 'test*.py'"
        )

        return result


    def analyze(self, result):

        if result["code"] == 0:

            return {
                "success": True,
                "message": "Tests passed"
            }


        return {
            "success": False,
            "message": result["error"]
        }


    def create_fix_task(self, error):

        return {
            "task": f"""
Fix the following error:

{error}

Inspect the affected files,
make the smallest safe change,
then run tests again.
"""
        }
