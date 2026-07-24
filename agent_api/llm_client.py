import os
import json
from agent_api.llm_provider import LLMProvider


class LLMClient:

    def __init__(self):
        self.provider = LLMProvider()


    def ask(self, prompt):

        response = self.provider.generate(
            prompt
        )

        if response["status"] != "success":
            return json.dumps({
                "files": [],
                "message": response["message"]
            })


        return response["response"]

