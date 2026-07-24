import os
import json


class LLMProvider:

    def __init__(self):

        self.api_key = os.getenv(
            "LLM_API_KEY"
        )


    def generate(self, prompt):

        if not self.api_key:

            return {
                "status": "error",
                "message": "No LLM_API_KEY configured"
            }


        # API request will be added here

        return {
            "status": "success",
            "response": json.dumps({
                "files": [],
                "message": "Model connection ready"
            })
        }
