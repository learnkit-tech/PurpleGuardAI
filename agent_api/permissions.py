ALLOWED_ACTIONS = [
    "read_file",
    "write_file",
    "run_command"
]


def allowed(action):

    return action in ALLOWED_ACTIONS
