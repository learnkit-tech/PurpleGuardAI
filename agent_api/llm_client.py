from agent_api.llm_provider import LLMProvider
from dev_agent.local_brain import LocalBrain
import json


class LLMClient:

    def __init__(self):

        self.provider = LLMProvider()
        self.local = LocalBrain()


    def ask(self, prompt):

        response = self.provider.generate(prompt)


        if response["status"] == "success":

            return response["response"]


        print("\nCloud AI unavailable.")
        print("Using local developer brain...")


        task = prompt.split("Task:")[-1]

        local_response = self.local.generate(
            task
        )

        return json.dumps(
            local_response
        )
