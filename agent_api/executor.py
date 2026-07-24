from agent_api import tools


def execute(action, data):

    if action == "read_file":
        return tools.read_file(
            data["path"]
        )

    elif action == "write_file":
        return tools.write_file(
            data["path"],
            data["content"]
        )

    elif action == "list_files":
        return tools.list_files(
            data.get("directory", ".")
        )

    elif action == "run_command":
        return tools.run_command(
            data["command"]
        )

    elif action == "git_status":
        return tools.git_status()

    else:
        return {
            "error": "Unknown action"
        }
