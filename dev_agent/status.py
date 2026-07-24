import json
import os


STATUS_FILE = "dev_agent/status.json"


def update_status(data):

    with open(STATUS_FILE, "w") as file:
        json.dump(data, file, indent=4)


def get_status():

    if not os.path.exists(STATUS_FILE):

        return {
            "status": "idle"
        }


    with open(STATUS_FILE, "r") as file:

        return json.load(file)
