import json


def get_next_task():

    with open("tasks/roadmap.json", "r") as file:
        tasks = json.load(file)

    for task in tasks:
        if task["status"] == "pending":
            return task

    return None
