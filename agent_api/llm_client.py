from agent_api.llm_provider import LLMProvider


class LLMClient:

    def __init__(self):

        self.provider = LLMProvider()


    def ask(self, prompt):

        result = self.provider.generate(
            prompt
        )


        if result["status"] == "error":

            return (
                "AI unavailable: "
                + result["message"]
            )


        return result["response"]
