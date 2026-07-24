import json


class CodeGenerator:

    def generate(self, task, ai_response):

        print("\nProcessing AI response...")

        try:
            change = json.loads(ai_response)

            return {
                "file": change.get("file"),
                "content": change.get("content"),
                "status": "ready"
            }

        except Exception:

            return {
                "file": None,
                "content": None,
                "status": "invalid",
                "message": "AI response was not valid JSON"
            }
