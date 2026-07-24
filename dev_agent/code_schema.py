import json


def parse_code_response(response):

    try:
        data = json.loads(response)

        if "files" not in data:
            return {
                "status": "error",
                "message": "No files field found"
            }

        return {
            "status": "success",
            "files": data["files"]
        }

    except Exception as error:

        return {
            "status": "error",
            "message": str(error)
        }
