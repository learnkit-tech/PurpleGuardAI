import os


class LLMProvider:

    def __init__(self):
        self.api_key = os.getenv(
            "LLM_API_KEY"
        )

        self.model = os.getenv(
            "LLM_MODEL",
            "default"
        )


    def generate(self, prompt):

        if not self.api_key:
            return {
                "status": "error",
                "message": "LLM API key not configured",
                "response": None
            }


        # API connection will be added here

        return {
            "status": "ready",
            "model": self.model,
            "response": "Provider connected but generation not implemented"
        }
