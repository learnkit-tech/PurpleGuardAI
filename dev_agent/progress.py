import json


FILE = "dev_agent/progress.json"


def save_progress(data):

    with open(FILE, "w") as file:
        json.dump(
            data,
            file,
            indent=4
        )


def load_progress():

    try:
        with open(FILE, "r") as file:
            return json.load(file)

    except FileNotFoundError:
        return {
            "completed": [],
            "current": None
        }
