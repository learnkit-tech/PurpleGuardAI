import difflib


def generate_diff(before, after):

    before_lines = before.splitlines()
    after_lines = after.splitlines()

    diff = difflib.unified_diff(
        before_lines,
        after_lines,
        fromfile="vulnerable",
        tofile="secure_fix",
        lineterm=""
    )

    return "\n".join(diff)
