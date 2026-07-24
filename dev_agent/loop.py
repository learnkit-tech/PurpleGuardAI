from dev_agent.planner import get_next_task
from dev_agent.memory import save_memory, load_memory
from agent_api.llm_client import LLMClient
from dev_agent.decision import DecisionEngine
from dev_agent.task_runner import TaskRunner
from dev_agent.prompt_builder import PromptBuilder
from dev_agent.code_generator import CodeGenerator
from dev_agent.change_manager import ChangeManager
from dev_agent.git_manager import GitManager


class DeveloperAgent:

    def __init__(self):

        self.ai = LLMClient()
        self.decision = DecisionEngine()
        self.runner = TaskRunner()
        self.prompt_builder = PromptBuilder()
        self.generator = CodeGenerator()
        self.changes = ChangeManager()
        self.git = GitManager()
        self.memory = load_memory()


    def run_once(self):

        task = get_next_task()

        if not task:
            print("No pending tasks.")
            return


        print("Current task:")
        print(task["task"])


        checkpoint = self.git.checkpoint()

        print("\nCheckpoint:")
        print(checkpoint)


        files = self.decision.execute_plan(
            {
                "action": "list_files",
                "data": {
                    "directory": "."
                }
            }
        )


        prompt = self.prompt_builder.build(
            task["task"],
            files
        )


        response = self.ai.ask(prompt)


        change = self.generator.generate(
            task["task"],
            response
        )


        result = self.changes.apply(change)

        print("\nChange result:")
        print(result)


        tests = self.runner.run(
            task["task"]
        )


        print("\nTests:")
        print(tests)


        self.memory["last_task"] = task["task"]

        save_memory(
            self.memory
        )
