from dev_agent.patcher import Patcher
from agent_api.tools import run_command


class TaskExecutor:

    def __init__(self):
        self.patcher = Patcher()


    def execute(self, task):

        print("Working on:")
        print(task)

        # placeholder until LLM generates code
        test_result = run_command(
            "python -m unittest discover -s tests -p 'test*.py'"
        )

        return test_result
