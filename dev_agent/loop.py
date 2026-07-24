from dev_agent.planner import get_next_task
from dev_agent.memory import save_memory, load_memory
from agent_api.llm_client import LLMClient
from dev_agent.decision import DecisionEngine
from dev_agent.prompt_builder import PromptBuilder
from dev_agent.code_generator import CodeGenerator
from dev_agent.change_manager import ChangeManager
from dev_agent.git_manager import GitManager
from dev_agent.self_corrector import SelfCorrector


class DeveloperAgent:

    def __init__(self):

        self.ai = LLMClient()
        self.decision = DecisionEngine()
        self.prompt_builder = PromptBuilder()
        self.generator = CodeGenerator()
        self.changes = ChangeManager()
        self.git = GitManager()
        self.corrector = SelfCorrector()
        self.memory = load_memory()


    def run_once(self):

        task = get_next_task()

        if not task:
            print("No pending tasks.")
            return


        print("Task:")
        print(task["task"])


        self.git.checkpoint()


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


        result = self.changes.apply(
            change
        )


        print("Change:")
        print(result)


        tests = self.corrector.run_tests()

        analysis = self.corrector.analyze(
            tests
        )


        print("Test result:")
        print(analysis)


        if not analysis["success"]:

            fix = self.corrector.create_fix_task(
                analysis["message"]
            )

            print("Fix task created:")
            print(fix)


        self.memory["last_task"] = task["task"]

        save_memory(
            self.memory
        )
