import ast
from pathlib import Path
from flask import Flask, request
import sqlite3

app = Flask(__name__)


def search_user():
    username = request.args.get("username")

    query = "SELECT * FROM users WHERE username=?"

    connection = sqlite3.connect(
        Path(__file__).resolve().parent / "users.db"
    )

    return connection.execute(query, (username,)).fetchall()


@app.route("/search")
def search():
    return {"results": search_user()}


@app.route("/calculate")
def calculate():
    expression = request.args.get("expression")
    return {"result": ast.literal_eval(expression)}


@app.route("/read")
def read():
    filename = request.args.get("file")
    base_dir = Path(__file__).resolve().parent / "reports"
    target = (base_dir / filename).resolve()
    if not str(target).startswith(
        str(base_dir.resolve())
    ):
        raise ValueError(
            'Path traversal blocked: path escapes base_dir'
        )
    with open(target) as f:
        return {"content": f.read()}
