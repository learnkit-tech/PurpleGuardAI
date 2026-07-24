import time
import json
import os

from dev_agent.run_agent import main
from dev_agent.status import update_status


ROADMAP = "tasks/roadmap.json"


def load_tasks():

    if not os.path.exists(ROADMAP):
        return []

    with open(ROADMAP, "r") as file:
        return json.load(file)


def save_tasks(tasks):

    with open(ROADMAP, "w") as file:
        json.dump(tasks, file, indent=4)


def run_worker():

    update_status({
        "status": "worker_started"
    })


    while True:

        tasks = load_tasks()

        pending = [
            task for task in tasks
            if task["status"] == "pending"
        ]


        if not pending:

            update_status({
                "status": "finished",
                "message": "All tasks completed"
            })

            break


        current = pending[0]


        update_status({
            "status": "building",
            "task": current["task"]
        })


        try:

            main(current["task"])


            current["status"] = "completed"

            save_tasks(tasks)


            update_status({
                "status": "completed",
                "task": current["task"]
            })


        except Exception as error:

            update_status({
                "status": "error",
                "task": current["task"],
                "message": str(error)
            })


        time.sleep(10)



if __name__ == "__main__":

    run_worker()
