import os
import subprocess


PROJECT_ROOT = "."


def read_file(path):

    full_path = os.path.join(
        PROJECT_ROOT,
        path
    )

    with open(full_path, "r") as file:
        return file.read()



def write_file(path, content):

    full_path = os.path.join(
        PROJECT_ROOT,
        path
    )

    with open(full_path, "w") as file:
        file.write(content)



def list_files(directory="."):

    files = []

    for root, dirs, filenames in os.walk(directory):

        for filename in filenames:
            files.append(
                os.path.join(root, filename)
            )

    return files



def run_command(command):

    result = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True
    )

    return {
        "output": result.stdout,
        "error": result.stderr,
        "code": result.returncode
    }



def git_status():

    return run_command(
        "git status"
    )

