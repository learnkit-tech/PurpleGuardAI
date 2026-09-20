from markupsafe import escape
import shlex
import os
import subprocess
import urllib.request
from pathlib import Path
from flask import Flask, Response, redirect, request

app = Flask(__name__)

# PG009 (SSRF) remediated by hand: the review queue flagged the
# unvalidated outbound fetch and this allowlist was chosen by the
# developer.
ALLOWED_FETCH_PREFIX = "https://api.internal.example"


@app.route("/run")
def run():
    command = request.args.get("command")
    result = subprocess.run(shlex.split(command), shell=False, capture_output=True, text=True)
    return {"output": result.stdout + result.stderr}


@app.route("/ping")
def ping():
    host = request.args.get("host")
    stream = subprocess.Popen(shlex.split('ping -c 1 ' + host), stdout=subprocess.PIPE, text=True).stdout
    return {"output": stream.read()}


@app.route("/greet")
def greet():
    name = request.args.get("name")
    return Response(escape("Hello " + name))


@app.route("/page")
def page():
    who = request.args.get("who")
    return Response(escape("<h1>Profile of " + who + "</h1>"))


@app.route("/go")
def go():
    next_url = request.args.get("next")
    if not next_url.startswith('/'):
        raise ValueError(
            'Open redirect blocked: only relative redirect targets are allowed'
        )
    return redirect(next_url)


@app.route("/jump")
def jump():
    destination = request.args.get("to")
    if not destination.startswith('/'):
        raise ValueError(
            'Open redirect blocked: only relative redirect targets are allowed'
        )
    return redirect(destination)


@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    if not url or not url.startswith(ALLOWED_FETCH_PREFIX):
        raise ValueError("SSRF blocked: destination not allowed")
    response = urllib.request.urlopen(url, timeout=2)
    return {"status": response.status, "body": response.read().decode()}
