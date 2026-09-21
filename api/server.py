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
from hacker.orchestrator import PurpleGuardSecurityOrchestrator

# dev_agent is optional — only needed for /agent/* endpoints
dev_agent_main = None
dev_agent_get_status = None
dev_agent_update_status = None
try:
    from dev_agent.run_agent import main as _dev_main
    from dev_agent.status import get_status as _dev_get, update_status as _dev_update
    dev_agent_main = _dev_main
    dev_agent_get_status = _dev_get
    dev_agent_update_status = _dev_update
except Exception:
    pass


app = Flask(__name__)


# ---------------------------------------------------------
# CORS
# ---------------------------------------------------------

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    return response


# ---------------------------------------------------------
# Health
# ---------------------------------------------------------

@app.route("/")
def home():
    return jsonify({
        "name": "PurpleGuardAI",
        "status": "online"
    })


@app.route("/status")
def status():
    return jsonify({
        "api": "online"
    })


# ---------------------------------------------------------
# Static security scanner
# ---------------------------------------------------------

@app.route("/scan", methods=["POST"])
def scan():

    data = request.get_json(silent=True) or {}
    target = data.get("target")

    if not target:
        return jsonify({
            "error": "target is required"
        }), 400

    target = os.path.abspath(
        os.path.expanduser(target)
    )

    if not os.path.isdir(target):
        return jsonify({
            "error": "target directory does not exist",
            "target": target
        }), 400

    try:
        scanner = SecurityScanner(target)
        results = scanner.scan()

        return jsonify({
            "status": "complete",
            "target": target,
            "findings": results,
            "count": len(results)
        })

    except Exception as error:

        return jsonify({
            "status": "error",
            "error": str(error)
        }), 500


# ---------------------------------------------------------
# Full PurpleGuard security workflow
#
# Discover
# → Validate
# → Confirm
# → Propose
# → Approve
# → Remediate
# → Rescan
# → Test
# → Re-attack
# → Verify
# ---------------------------------------------------------

@app.route("/secure", methods=["POST"])
def secure():

    data = request.get_json(silent=True) or {}

    target = data.get("target")
    approved = bool(data.get("approved", False))

    if not target:
        return jsonify({
            "error": "target is required"
        }), 400

    target = os.path.abspath(
        os.path.expanduser(target)
    )

    if not os.path.isdir(target):
        return jsonify({
            "error": "target directory does not exist",
            "target": target
        }), 400

    try:

        orchestrator = PurpleGuardSecurityOrchestrator(
            target
        )

        result = orchestrator.run(
            approved=approved
        )

        return jsonify(result)

    except Exception as error:

        return jsonify({
            "status": "error",
            "error": str(error)
        }), 500


# ---------------------------------------------------------
# Autonomous developer agent
# ---------------------------------------------------------

@app.route("/agent/status")
def agent_status():

    if dev_agent_get_status is None:
        return jsonify({"error": "dev_agent not available"}), 503
    return jsonify(
        dev_agent_get_status()
    )


@app.route("/agent/run", methods=["POST"])
def agent_run():

    if dev_agent_main is None:
        return jsonify({"error": "dev_agent not available"}), 503

    def run_agent():

        dev_agent_update_status({
            "status": "running"
        })

        try:

            dev_agent_main()

            dev_agent_update_status({
                "status": "completed"
            })

        except Exception as error:

            dev_agent_update_status({
                "status": "error",
                "message": str(error)
            })


    thread = threading.Thread(
        target=run_agent,
        daemon=True
    )

    thread.start()

    return jsonify({
        "message": "Agent started"
    })


# ---------------------------------------------------------
# Start API
# ---------------------------------------------------------

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=8000,
        debug=False
    )
