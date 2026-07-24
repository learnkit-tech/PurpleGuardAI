from dev_agent.coder import CodeWriter
from agent_api.tools import run_command


class TaskRunner:

    def __init__(self):
        self.coder = CodeWriter()


    def run(self, task):

        print("Executing:")
        print(task)


        # temporary autonomous workflow
        tests = run_command(
            "python -m unittest discover -s tests -p 'test*.py'"
        )


        print(tests)

        return tests
