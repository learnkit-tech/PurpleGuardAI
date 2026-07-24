import os
import requests


class LLMProvider:

    def __init__(self):

        self.api_key = os.getenv(
            "OPENAI_API_KEY"
        )

        self.url = "https://api.openai.com/v1/chat/completions"


    def generate(self, prompt):

        if not self.api_key:

            return {
                "status": "error",
                "message": "OPENAI_API_KEY missing"
            }


        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }


        data = {
            "model": "gpt-4.1-mini",
            "messages": [
                {
                    "role": "system",
                    "content": "You are a senior software engineer. Return only valid JSON."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        }


        response = requests.post(
            self.url,
            headers=headers,
            json=data
        )


        result = response.json()


        if "error" in result:

            return {
                "status": "error",
                "message": result["error"]["message"]
            }


        if "choices" not in result:

            return {
                "status": "error",
                "message": str(result)
            }


        return {
            "status": "success",
            "response": result["choices"][0]["message"]["content"]
        }
