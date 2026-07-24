import os
import json


class LLMClient:

    def __init__(self):

        self.provider = os.getenv(
            "AI_PROVIDER",
            "none"
        )


    def ask(self, prompt):

        if self.provider == "none":

            return json.dumps(
                {
                    "file": None,
                    "content": None,
                    "message": "No AI provider connected yet"
                }
            )


        return json.dumps(
            {
                "file": None,
                "content": None,
                "message": "Provider not implemented"
            }
        )
