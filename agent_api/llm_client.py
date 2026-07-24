from agent_api.llm_provider import LLMProvider


class LLMClient:

    def __init__(self):
        self.provider = LLMProvider()


    def ask(self, prompt):

        response = self.provider.generate(prompt)

        print("\nRAW AI RESPONSE:")
        print(response)

        if response["status"] != "success":
            return '{"files": []}'

        return response["response"]
