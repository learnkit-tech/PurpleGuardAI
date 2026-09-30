import json
import os


STATUS_FILE = "dev_agent/status.json"


def update_status(data, path=None):

    status_path = path or STATUS_FILE

    with open(status_path, "w") as file:
        json.dump(data, file, indent=4)


def get_status():

    if not os.path.exists(STATUS_FILE):

        return {
            "status": "idle"
        }

    try:

        with open(STATUS_FILE, "r") as file:

            return json.load(file)

    except (ValueError, OSError):

        # An empty or unreadable status file must not crash every
        # consumer (worker loop, coordination stage); treat as idle.
        return {
            "status": "idle"
        }


def security_completion_status(task_text, status):
    """Roadmap completion state for a finished loop invocation.

    A security coordination task that ended at "awaiting_approval"
    stays open for a human instead of being marked completed, so the
    worker neither reports success nor re-runs it autonomously.
    """

    coordination = (status.get("security_coordination") or {})

    if (
        coordination.get("task") == task_text
        and coordination.get("stage") == "awaiting_approval"
    ):
        return "awaiting_approval"

    return "completed"
