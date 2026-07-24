import sys
import os
import threading

sys.path.append(
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )
)

from flask import Flask, jsonify, request
from scanner.engine import SecurityScanner
from dev_agent.run_agent import main
from dev_agent.status import get_status, update_status


app = Flask(__name__)


@app.route("/")
def home():

    return jsonify({
        "name": "PurpleGuardAI",
        "status": "online"
    })


@app.route("/scan", methods=["POST"])
def scan():

    data = request.json

    target = data.get("target")

    scanner = SecurityScanner(target)

    results = scanner.scan()

    return jsonify({
        "findings": results
    })


@app.route("/status")
def status():

    return jsonify({
        "api": "online"
    })


@app.route("/agent/status")
def agent_status():

    return jsonify(
        get_status()
    )


@app.route("/agent/run", methods=["POST"])
def agent_run():

    def run_agent():

        update_status({
            "status": "running"
        })

        try:

            main()

            update_status({
                "status": "completed"
            })


        except Exception as error:

            update_status({
                "status": "error",
                "message": str(error)
            })


    thread = threading.Thread(
        target=run_agent
    )

    thread.start()


    return jsonify({
        "message": "Agent started"
    })


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=8000
    )
