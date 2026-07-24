import json


def parse_code_response(response):

    if not response:
        return {
            "status": "error",
            "message": "Empty AI response"
        }


    try:

        data = json.loads(response)


        if "files" not in data:

            return {
                "status": "error",
                "message": "AI response missing files field"
            }


        return {
            "status": "success",
            "files": data["files"]
        }


    except json.JSONDecodeError:

        return {
            "status": "error",
            "message": "AI response was not valid JSON",
            "raw": response
        }
