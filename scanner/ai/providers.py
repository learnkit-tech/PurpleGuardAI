from .interface import AIProvider


class MockAI(AIProvider):

    def analyze(self, prompt):

        return {
            "analysis": "AI analysis placeholder",
            "confidence": 0.80
        }


class OpenAIProvider(AIProvider):

    def __init__(self, client):
        self.client = client


    def analyze(self, prompt):

        response = self.client.responses.create(
            model="your-model",
            input=prompt
        )

        return response.output_text
