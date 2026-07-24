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
                    "content": """
You are an autonomous senior software engineer.
Return ONLY valid JSON.

Format:
{
 "files": [
  {
   "path": "file/path.py",
   "content": "complete code"
  }
 ]
}
"""
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


        return {
            "status": "success",
            "response": result["choices"][0]["message"]["content"]
        }
