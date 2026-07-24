import json
import os


def load_vulnerabilities():

    path = os.path.join(
        os.path.dirname(__file__),
        "vulnerabilities.json"
    )

    with open(path, "r") as file:
        return json.load(file)
