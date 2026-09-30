import sys
import os
import subprocess
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

# dev_agent is optional — only needed for /agent/* endpoints.
# The two probes are split so a missing optional dependency in the
# full agent loop (e.g. `requests` via agent_api.llm_provider) does
# not take down the lightweight status endpoint with it.
# IMPORTANT: never import dev_agent.run_agent here — that module tags
# its process as the autonomous approval surface (PG_EXEC_SURFACE),
# and this API process must stay untagged so frontend /secure
# approvals keep working. The loop runs in a subprocess instead; the
# run-availability probe imports the loop module itself, which sets
# no tag.
dev_agent_get_status = None
dev_agent_update_status = None
dev_agent_available = False
try:
    from dev_agent.status import get_status as _dev_get, update_status as _dev_update
    dev_agent_get_status = _dev_get
    dev_agent_update_status = _dev_update
except Exception:
    pass
try:
    from dev_agent.loop import DeveloperAgent as _dev_agent_cls
    dev_agent_available = True
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
# Reset test fixture to vulnerable state
# ---------------------------------------------------------

@app.route("/reset", methods=["POST"])
def reset_fixture():
    """Reset the web test fixture to its vulnerable state.

    This exists so the demo can show real vulnerabilities.
    The fixture ships in a guarded state for tests; this
    endpoint restores the vulnerable patterns.
    """
    import subprocess
    fixture_dir = os.path.join(
        os.path.dirname(os.path.dirname(
            os.path.abspath(__file__)
        )),
        "tests", "hacker_target_web"
    )
    reset_script = os.path.join(fixture_dir, "reset_vulnerable.py")
    if not os.path.exists(reset_script):
        return jsonify({"error": "reset script not found"}), 404
    result = subprocess.run(
        [sys.executable, reset_script],
        capture_output=True, text=True, timeout=10
    )
    return jsonify({
        "status": "ok",
        "message": result.stdout.strip() or "Fixture reset"
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

    if not dev_agent_available:
        return jsonify({"error": "dev_agent not available"}), 503

    def run_agent():

        dev_agent_update_status({
            "status": "running"
        })

        try:

            # Run the loop in its own process. dev_agent/run_agent.py
            # tags that process tree as the autonomous surface
            # (PG_EXEC_SURFACE), which purpleguard_runner refuses to
            # approve. Isolating it here keeps THIS api process
            # untagged, so frontend approvals via /secure are never
            # affected by an agent run.
            project_root = os.path.dirname(
                os.path.dirname(os.path.abspath(__file__))
            )
            completed = subprocess.run(
                [sys.executable, "-m", "dev_agent.run_agent"],
                cwd=project_root,
                capture_output=True,
                text=True,
                timeout=1800,
            )

            if completed.returncode == 0:
                dev_agent_update_status({
                    "status": "completed"
                })
            else:
                dev_agent_update_status({
                    "status": "error",
                    "message": (completed.stderr or "agent run failed")[-500:],
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
