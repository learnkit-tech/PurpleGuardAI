from pathlib import Path

APP = '''import os
import pickle
import subprocess
import urllib.request
from pathlib import Path
from flask import Flask, Response, redirect, request

app = Flask(__name__)


@app.route("/run")
def run():
    command = request.args.get("command")
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return {"output": result.stdout + result.stderr}


@app.route("/ping")
def ping():
    host = request.args.get("host")
    stream = os.popen("ping -c 1 " + host)
    return {"output": stream.read()}


@app.route("/greet")
def greet():
    name = request.args.get("name")
    return Response("Hello " + name)


@app.route("/page")
def page():
    who = request.args.get("who")
    return Response("<h1>Profile of " + who + "</h1>")


@app.route("/go")
def go():
    next_url = request.args.get("next")
    return redirect(next_url)


@app.route("/jump")
def jump():
    destination = request.args.get("to")
    return redirect(destination)


@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    try:
        response = urllib.request.urlopen(url, timeout=2)
        return {"status": response.status, "body": response.read().decode()}
    except Exception as exc:
        return {"error": f"{url}: {exc}"}


@app.route("/load", methods=["POST"])
def load():
    data = request.get_data()
    try:
        obj = pickle.loads(data)
        return {"loaded": str(obj)}
    except Exception as exc:
        return {"error": f"deserialization failed: {exc}"}
'''

Path(__file__).with_name("web_app.py").write_text(APP)

print("Vulnerable web test fixture restored.")
