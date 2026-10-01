import sys
import os
import subprocess
import threading
from pathlib import Path

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
# Security Agent Workforce (real engine path)
#
# These endpoints expose the PurpleGuard-native workforce through the
# SAME backend that already serves /scan and /secure. They run the
# real engines and return actual execution state and evidence.
#
# Security posture (unchanged from the rest of this API):
#   * every endpoint validates its target and returns deterministic
#     error payloads;
#   * the read endpoints never write anything;
#   * workflow state lives under a configurable directory so tests and
#     deployments can isolate it (PURPLEGUARD_WORKFORCE_DIR);
#   * source is never modified except through the explicit approval
#     endpoint, and never without approve == true.
# ---------------------------------------------------------

def _workforce_state_dir():
    base = os.environ.get("PURPLEGUARD_WORKFORCE_DIR")
    return Path(base) if base else None


def _workforce_orchestrator():
    from security_workforce import WorkforceOrchestrator, WorkforceStore

    state = _workforce_state_dir()
    if state is None:
        return WorkforceOrchestrator()
    return WorkforceOrchestrator(
        store=WorkforceStore(state / "security_workforce.json")
    )


def _workforce_handoff(workforce):
    from security_workforce import DeveloperHandoff

    state = _workforce_state_dir()
    if state is None:
        return DeveloperHandoff(workforce.store)
    return DeveloperHandoff(
        workforce.store,
        handoff_path=state / "handoff.json",
        status_path=state / "dev_status.json",
    )


def _resolve_target(raw):
    """Shared target validation. Returns (target, error_response)."""
    if not raw or not str(raw).strip():
        return None, (jsonify({"error": "target is required"}), 400)

    target = os.path.abspath(os.path.expanduser(str(raw)))

    if not os.path.isdir(target):
        return None, (jsonify({
            "error": "target directory does not exist",
            "target": target,
        }), 400)

    return target, None


@app.route("/workforce/capabilities")
def workforce_capabilities():
    try:
        workforce = _workforce_orchestrator()
        return jsonify({
            "status": "ok",
            "capabilities": workforce.capabilities(),
        })
    except Exception as error:
        return jsonify({"status": "error", "error": str(error)}), 500


@app.route("/workforce/findings")
def workforce_findings():
    try:
        workforce = _workforce_orchestrator()
        findings = workforce.canonical_findings()
        return jsonify({
            "status": "ok",
            "count": len(findings),
            "findings": findings,
        })
    except Exception as error:
        return jsonify({"status": "error", "error": str(error)}), 500


@app.route("/workforce/assess", methods=["POST"])
def workforce_assess():
    data = request.get_json(silent=True) or {}

    target, error = _resolve_target(data.get("target"))
    if error is not None:
        return error

    try:
        workforce = _workforce_orchestrator()
        assessment = workforce.assess(
            target, approved=bool(data.get("approved", False))
        )
        return jsonify({"status": "ok", "assessment": assessment})
    except Exception as error:
        return jsonify({"status": "error", "error": str(error)}), 500


@app.route("/workforce/handoff", methods=["GET", "POST"])
def workforce_handoff():
    """GET: pending developer items. POST: send canonical findings.

    Neither applies remediation: approval is an explicit, separate step.
    """
    try:
        workforce = _workforce_orchestrator()
        handoff = _workforce_handoff(workforce)

        if request.method == "GET":
            return jsonify({
                "status": "ok",
                "pending": handoff.pending(),
            })

        data = request.get_json(silent=True) or {}
        target, error = _resolve_target(data.get("target"))
        if error is not None:
            return error

        result = handoff.send(workforce.canonical_findings(), target=target)
        return jsonify({"status": "ok", **result})
    except Exception as error:
        return jsonify({"status": "error", "error": str(error)}), 500


@app.route("/workforce/approve", methods=["POST"])
def workforce_approve():
    """Explicit human approval -> remediation -> genuine re-test.

    Without ``approve`` true this returns APPROVAL_REQUIRED and modifies
    nothing. With it, remediation runs and a real re-test decides the
    verdict; the endpoint never marks a finding verified by itself.
    """
    data = request.get_json(silent=True) or {}
    fingerprint = data.get("fingerprint")

    if not fingerprint:
        return jsonify({"error": "fingerprint is required"}), 400

    try:
        workforce = _workforce_orchestrator()
        handoff = _workforce_handoff(workforce)

        if handoff.get(fingerprint) is None:
            return jsonify({
                "status": "NOT_FOUND",
                "fingerprint": fingerprint,
            }), 404

        result = handoff.approve_and_remediate(
            fingerprint,
            approve=bool(data.get("approve", False)),
            target=data.get("target"),
        )
        return jsonify({"status": "ok", **result})
    except Exception as error:
        return jsonify({"status": "error", "error": str(error)}), 500


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
