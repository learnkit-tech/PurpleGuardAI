import json
import os


ROADMAP_FILE = "tasks/roadmap.json"


class RoadmapManager:

    def __init__(self):
        self.tasks = self.load()


    def load(self):

        if not os.path.exists(ROADMAP_FILE):
            return []

        with open(ROADMAP_FILE, "r") as file:
            return json.load(file)


    def save(self):

        with open(ROADMAP_FILE, "w") as file:
            json.dump(
                self.tasks,
                file,
                indent=4
            )


    def next_task(self):

        for task in self.tasks:
            if task["status"] == "pending":
                return task

        return None


    def complete(self, task_id):

        for task in self.tasks:
            if task["id"] == task_id:
                task["status"] = "completed"

        self.save()

