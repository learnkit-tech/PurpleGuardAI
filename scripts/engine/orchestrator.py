#!/usr/bin/env python3
"""PurpleGuard engine loop (Python) — contract per docs/ENGINE_API.md.

This is the ENGINE side of the runs loop. It is intentionally honest:
it performs NO scanning and fabricates NO findings. Where a real validator
must act, it prints exactly what the run/approval/revalidation requires.
Replace the marked `# === REAL ENGINE WORK ===` sections with orchestrator.py
validation logic; the transport, auth, claim/resolve plumbing, and verdict
write-backs below are production-ready as-is.

Contract summary:
    GET  /api/runs/pending        queued runs (oldest first)
    POST /api/runs/claim          atomic claim; response carries the run SCOPE
    POST /api/ingest_finding      push one finding (requires id + attackSteps)
    POST /api/runs/resolve        run outcome + findingsIngested count
    GET  /api/approvals/pending   developer-approved buffers (ai | manual)
    POST /api/approvals/resolve   verdict: VERIFIED_FIXED | STILL_VULNERABLE
    GET  /api/revalidate/pending  queued fresh re-attacks
    POST /api/revalidate/resolve  verdict write-back

Usage:
    export SITE="https://expert-elk-927.convex.site"
    export ENGINE_API_KEY="<value of ENGINE_API_KEY env var on the deployment>"
    export GITHUB_TOKEN="ghp_..."          # optional: enables repo fetch
    python3 orchestrator.py --once         # single poll pass
    python3 orchestrator.py                # loop every POLL_INTERVAL_SECONDS

Every request must carry X-Engine-Key. SITE must be the *.convex.site origin,
NOT *.convex.cloud (the .cloud host serves queries/mutations, not /api/*).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

# Real validators live alongside this file (scripts/engine/validators.py).
from validators import validate  # noqa: E402

SITE = os.environ.get("SITE", "").rstrip("/")
KEY = os.environ.get("ENGINE_API_KEY", "")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
POLL_INTERVAL_SECONDS = int(os.environ.get("POLL_INTERVAL_SECONDS", "15"))


def _require_env() -> None:
    """Validated at call time (not import time) so the module can be
    imported by tests and tooling without deployment credentials."""
    if not SITE or not KEY:
        print(
            "Usage: SITE=https://<deployment>.convex.site ENGINE_API_KEY=<key> "
            "python3 orchestrator.py [--once]",
            file=sys.stderr,
        )
        sys.exit(1)


def log(msg: str) -> None:
    print(f"[orchestrator {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}] {msg}", flush=True)


def api(path: str, method: str = "GET", body: Optional[Dict[str, Any]] = None) -> Any:
    _require_env()
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        f"{SITE}{path}",
        data=data,
        method=method,
        headers={
            "Content-Type": "application/json",
            "X-Engine-Key": KEY,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as res:
            return json.loads(res.read().decode())
    except urllib.error.HTTPError as e:
        detail = e.read().decode()[:300]
        raise RuntimeError(f"{method} {path} -> {e.code}: {detail}") from e


# ---------------------------------------------------------------------------
# Finding push (docs/ENGINE_API.md section 1)
# ---------------------------------------------------------------------------

def ingest_finding(payload: Dict[str, Any]) -> Any:
    if "id" not in payload or not payload.get("attackSteps"):
        raise ValueError(
            "finding payload needs 'id' and non-empty 'attackSteps' — "
            "verdicts must come from reverification.py, never be invented"
        )
    return api("/api/ingest_finding", method="POST", body=payload)


# ---------------------------------------------------------------------------
# Repo fetch helper (optional convenience; requires GITHUB_TOKEN for private)
# ---------------------------------------------------------------------------

def fetch_repo_files(repo: str) -> List[Dict[str, Any]]:
    """List {path, content} entries for the repo's default branch.
    Public repos fetch anonymously; private repos need GITHUB_TOKEN.
    Returns [] when a token is required but unset (honest: no work done)."""
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

    files: List[Dict[str, Any]] = []

    def gh(url: str) -> Any:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as res:
            return json.loads(res.read().decode())

    def walk(tree_url: str, prefix: str = "") -> None:
        tree = gh(tree_url)
        for item in tree.get("tree", []):
            if item["type"] == "blob":
                if item["size"] > 200_000:  # skip large blobs
                    continue
                blob = gh(item["url"])
                import base64
                content = base64.b64decode(blob.get("content", "")).decode(
                    "utf-8", errors="replace"
                )
                files.append({"path": prefix + item["path"], "content": content})
            elif item["type"] == "tree" and item["path"] not in (
                ".git", "node_modules", "dist", "build",
            ):
                walk(item["url"], prefix + item["path"] + "/")

    repo_meta = gh(f"https://api.github.com/repos/{repo}")
    branch = repo_meta.get("default_branch", "main")
    walk(f"https://api.github.com/repos/{repo}/git/trees/{branch}?recursive=1")
    return files


# ---------------------------------------------------------------------------
# The loop
# ---------------------------------------------------------------------------

def claim_run(run: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    try:
        claim = api("/api/runs/claim", method="POST", body={
            "runId": run["_id"],
            "engineRunId": f"py-{int(time.time())}",
        })
    except RuntimeError as e:
        log(f"claim {run['_id']} failed: {e}")
        return None
    if not claim.get("ok"):
        log(f"run {run['_id']} not claimable: {claim.get('reason')}")
        return None
    return claim


def handle_run(run: Dict[str, Any], dry_run: bool) -> None:
    claim = claim_run(run)
    if claim is None:
        return
    scope = claim.get("scope") or {"authorizedPaths": [], "blockedPaths": []}
    log(
        f"claimed run {run['_id']} project={claim['projectId']} kind={claim['kind']} "
        f"authorized={json.dumps(scope.get('authorizedPaths', []))} "
        f"blocked={json.dumps(scope.get('blockedPaths', []))}"
    )
    project = claim["projectId"]
    authorized: List[str] = scope.get("authorizedPaths", [])

    if dry_run:
        # A dry run must never fetch+validate: it only verifies wiring and
        # honestly reports that NO validation was executed.
        api("/api/runs/resolve", method="POST", body={
            "runId": run["_id"],
            "ok": False,
            "note": "python orchestrator dry run — wiring verified, no validation executed",
            "findingsIngested": 0,
        })
        log(f"resolved run {run['_id']} as ok:false (dry run)")
        return

    # --- REAL VALIDATION PATH -------------------------------------------
    # 1. Fetch the authorized target (repo files via GitHub).
    # 2. validate() applies the scope FIRST: only files matching
    #    authorizedPaths (and not blockedPaths) are ever inspected.
    # 3. Every finding is real matched code with evidence; push each one.
    # 4. Resolve with the true count (0 findings = ok, honest outcome).
    # ---------------------------------------------------------------------
    try:
        files = fetch_repo_files(project)
    except Exception as e:  # fetch failure is an honest run failure
        api("/api/runs/resolve", method="POST", body={
            "runId": run["_id"],
            "ok": False,
            "note": f"target fetch failed: {e}",
            "findingsIngested": 0,
        })
        log(f"resolved run {run['_id']} ok:false — fetch failed")
        return

    if not files:
        api("/api/runs/resolve", method="POST", body={
            "runId": run["_id"],
            "ok": False,
            "note": (
                "target not fetchable (empty repo, or GITHUB_TOKEN unset for "
                "a private repo) — no validation executed"
            ),
            "findingsIngested": 0,
        })
        log(f"resolved run {run['_id']} ok:false — no target files")
        return

    findings = validate(project, files, scope)
    log(f"validators produced {len(findings)} finding(s) for {project}")

    pushed = 0
    errors = []
    for f in findings:
        try:
            ingest_finding(f)
            pushed += 1
        except (RuntimeError, ValueError) as e:
            # One bad finding must not kill the run; record and continue.
            errors.append(f"{f.get('id')}: {e}")
            log(f"ingest failed for {f.get('id')}: {e}")

    note = f"{pushed} finding(s) pushed"
    if errors:
        note += f"; {len(errors)} ingest error(s)"
    api("/api/runs/resolve", method="POST", body={
        "runId": run["_id"],
        "ok": True,
        "note": note,
        "findingsIngested": pushed,
    })
    log(f"resolved run {run['_id']} ok:true findingsIngested={pushed}")



def handle_approvals() -> None:
    try:
        approvals = api("/api/approvals/pending").get("approvals", [])
    except RuntimeError as e:
        log(f"approvals/pending failed: {e}")
        return
    for a in approvals:
        # === REAL ENGINE WORK: apply buffer, re-attack, resolve ============
        # code = a["code"]; apply to the finding's file; run reverification;
        # verdict = "VERIFIED_FIXED" if all steps blocked else "STILL_VULNERABLE"
        # api("/api/approvals/resolve", method="POST", body={
        #     "approvalId": a["_id"], "verdict": verdict,
        #     "attackSteps": [{"name": s["name"], "verdict": "blocked"}, ...],
        # })
        log(
            f"PENDING approval {a['_id']} finding={a['findingId']} source={a['source']} "
            f"({len(a.get('code', ''))} chars) — apply buffer, re-attack, then resolve"
        )


def handle_revalidations() -> None:
    try:
        revals = api("/api/revalidate/pending").get("revalidations", [])
    except RuntimeError as e:
        log(f"revalidate/pending failed: {e}")
        return
    for r in revals:
        # === REAL ENGINE WORK: fresh re-attack, then resolve ===============
        # api("/api/revalidate/resolve", method="POST", body={
        #     "revalidationId": r["_id"], "verdict": ..., "attackSteps": [...],
        # })
        log(
            f"PENDING revalidation {r['_id']} finding={r['findingId']} — "
            "re-attack, then POST /api/revalidate/resolve"
        )


def poll_pass(dry_run: bool) -> bool:
    try:
        runs = api("/api/runs/pending").get("runs", [])
    except RuntimeError as e:
        log(f"runs/pending failed: {e}")
        return False
    if not runs:
        log("no queued runs")
    for run in runs:
        handle_run(run, dry_run)
    handle_approvals()
    handle_revalidations()
    return bool(runs)


def main() -> None:
    _require_env()
    parser = argparse.ArgumentParser(description="PurpleGuard engine loop")
    parser.add_argument("--once", action="store_true", help="single poll pass")
    parser.add_argument(
        "--dry-run", action="store_true",
        help="claim runs, observe scope, resolve ok:false — no validation",
    )
    args = parser.parse_args()

    log(f"starting against {SITE}{' (dry-run)' if args.dry_run else ''}")
    had_work = True
    while not args.once:
        if not had_work:
            time.sleep(POLL_INTERVAL_SECONDS)
        try:
            had_work = poll_pass(args.dry_run)
        except Exception as e:  # keep the loop alive
            log(f"poll pass error: {e}")
            had_work = False
            time.sleep(POLL_INTERVAL_SECONDS)
        if args.once:
            break
    if args.once:
        try:
            poll_pass(args.dry_run)
        except Exception as e:
            log(f"poll pass error: {e}")
    log("done")


if __name__ == "__main__":
    main()
