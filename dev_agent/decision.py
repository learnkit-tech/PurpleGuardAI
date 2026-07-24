from agent_api.executor import execute


class DecisionEngine:

    def decide(self, task):

        print("Analyzing task:")
        print(task)

        # Placeholder until we connect a real LLM
        plan = {
            "action": "list_files",
            "data": {
                "directory": "."
            }
        }

        return plan


    def execute_plan(self, plan):

        return execute(
            plan["action"],
            plan["data"]
        )
