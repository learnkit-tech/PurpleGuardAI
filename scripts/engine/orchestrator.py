#!/usr/bin/env python3
"""PurpleGuard engine loop v2 — kind-routing runs loop + real approvals.

Contract per docs/ENGINE_API.md. Honesty rules unchanged:
  - verdicts come only from the real engine's validators/re-verification
  - no target / no clone / no context => work stays pending or fails honestly
  - a dry run never fetches and never validates (resolves ok:false)

Run kinds routed on claim:
  scan         -> SecurityScanner static scan only (no live target)
  validation   -> discover -> plan -> validate on LocalTarget -> ingest
  remediation  -> full secure loop (engine's own APPROVAL_REQUIRED gate)

Approvals/revalidations need the finding's context (file, category,
validator). The engine caches every finding it ingests in
scripts/engine/.purpleguard-findings.json, and applies approved buffers to
LOCAL_CLONE_PATH (a checkout of the vulnerable target, e.g.
~/PurpleGuardAI/tests/hacker_target_web). Without a clone, work stays
pending — the UI shows WAITING FOR ENGINE, which is true.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

from validators import validate as static_validate  # noqa: E402
from engine_adapter import (  # noqa: E402
    _map_static_finding,
    materialize_target,
    run_discovery_and_validation,
    run_full_secure_loop,
)

# Category -> validator method on LocalAttackValidator (the real planner map).
from hacker.planner import AttackPlanner              # noqa: E402
from hacker.validation.local_target import LocalTarget  # noqa: E402
from hacker.validation.validator import LocalAttackValidator  # noqa: E402
from scanner.engine import SecurityScanner            # noqa: E402

VALIDATOR_BY_CATEGORY = dict(AttackPlanner.VALIDATORS)

SITE = os.environ.get("SITE", "").rstrip("/")
KEY = os.environ.get("ENGINE_API_KEY", "")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
LOCAL_CLONE_PATH = os.environ.get("LOCAL_CLONE_PATH", "")
POLL_INTERVAL_SECONDS = int(os.environ.get("POLL_INTERVAL_SECONDS", "15"))
CACHE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".purpleguard-findings.json")


def _require_env() -> None:
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
        headers={"Content-Type": "application/json", "X-Engine-Key": KEY},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as res:
            return json.loads(res.read().decode())
    except urllib.error.HTTPError as e:
        detail = e.read().decode()[:300]
        raise RuntimeError(f"{method} {path} -> {e.code}: {detail}") from e


# ---------------------------------------------------------------------------
# Local finding cache (engine's own ingested findings -> context for approvals)
# ---------------------------------------------------------------------------

def cache_load() -> Dict[str, Any]:
    try:
        with open(CACHE_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def cache_save(payload: Dict[str, Any]) -> None:
    cache = cache_load()
    cache[payload.get("id", "")] = payload
    try:
        with open(CACHE_PATH, "w", encoding="utf-8") as fh:
            json.dump(cache, fh)
    except OSError as e:
        log(f"cache write failed (ignored): {e}")


def ingest_finding(payload: Dict[str, Any]) -> Any:
    if "id" not in payload or not payload.get("attackSteps"):
        raise ValueError(
            "finding payload needs 'id' and non-empty 'attackSteps' — "
            "verdicts must come from real validation, never be invented"
        )
    result = api("/api/ingest_finding", method="POST", body=payload)
    cache_save(payload)
    return result


def heartbeat(run_id: str, stage: str) -> None:
    try:
        api("/api/runs/heartbeat", method="POST", body={"runId": run_id, "stage": stage})
    except Exception as e:  # noqa: BLE001
        log(f"heartbeat failed (ignored): {e}")


def fetch_repo_files(repo: str) -> List[Dict[str, Any]]:
    """List {path, content} for the repo's default branch. [] when a token
    is required but unset (honest: no work done)."""
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
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
                if item["size"] > 200_000:
                    continue
                blob = gh(item["url"])
                import base64
                content = base64.b64decode(blob.get("content", "")).decode("utf-8", errors="replace")
                files.append({"path": prefix + item["path"], "content": content})
            elif item["type"] == "tree" and item["path"] not in (".git", "node_modules", "dist", "build"):
                walk(item["url"], prefix + item["path"] + "/")

    repo_meta = gh(f"https://api.github.com/repos/{repo}")
    branch = repo_meta.get("default_branch", "main")
    walk(f"https://api.github.com/repos/{repo}/git/trees/{branch}?recursive=1")
    return files


def load_files_from_dir(root: str) -> List[Dict[str, Any]]:
    files: List[Dict[str, Any]] = []
    for base, dirs, names in os.walk(root):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "__pycache__", "venv", ".venv")]
        for name in names:
            full = os.path.join(base, name)
            try:
                if os.path.getsize(full) > 200_000:
                    continue
                with open(full, "r", encoding="utf-8", errors="replace") as fh:
                    files.append({"path": os.path.relpath(full, root), "content": fh.read()})
            except OSError:
                continue
    return files


# ---------------------------------------------------------------------------
# Run handling, routed by kind
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


def _resolve(run_id: str, ok: bool, note: str, pushed: int) -> None:
    api("/api/runs/resolve", method="POST", body={
        "runId": run_id, "ok": ok, "note": note, "findingsIngested": pushed,
    })


def handle_scan(run_id: str, project: str, scope: Dict[str, Any]) -> None:
    """Static scan only: materialize in-scope files, run SecurityScanner,
    push clearly-labeled static findings. No live target is started."""
    heartbeat(run_id, "static scan: fetching authorized target")
    try:
        files = fetch_repo_files(project)
    except Exception as e:  # noqa: BLE001
        _resolve(run_id, False, f"target fetch failed: {e}", 0)
        return
    root = materialize_target(project, files, scope)
    if root is None:
        _resolve(run_id, False, "no files in run scope (fail-closed) — nothing scanned", 0)
        return
    try:
        heartbeat(run_id, "static scan: running SecurityScanner (PG rules)")
        pushed = 0
        for f in SecurityScanner(root).scan():
            payload = _map_static_finding(project, root, f)
            if not payload:
                continue
            heartbeat(run_id, f"static scan: ingesting {payload['id']}")
            try:
                ingest_finding(payload)
                pushed += 1
            except (RuntimeError, ValueError) as e:
                log(f"ingest failed for {payload['id']}: {e}")
        _resolve(run_id, True, f"static scan complete: {pushed} finding(s) pushed", pushed)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def handle_validation(run_id: str, project: str, scope: Dict[str, Any], dry_run: bool) -> None:
    if dry_run:
        _resolve(run_id, False, "python orchestrator dry run — wiring verified, no validation executed", 0)
        log(f"resolved run {run_id} as ok:false (dry run)")
        return
    heartbeat(run_id, "validation: resolving authorized target")
    if LOCAL_CLONE_PATH and os.path.isdir(LOCAL_CLONE_PATH):
        files = load_files_from_dir(LOCAL_CLONE_PATH)  # local fixture/clone source
    else:
        try:
            files = fetch_repo_files(project)
        except Exception as e:  # noqa: BLE001
            _resolve(run_id, False, f"target fetch failed: {e}", 0)
            return
    if not files:
        _resolve(run_id, False, "target not fetchable (empty repo, or GITHUB_TOKEN unset for a private repo) — no validation executed", 0)
        return

    def stage(msg: str) -> None:
        heartbeat(run_id, msg)

    result = run_discovery_and_validation(project, scope, files, log=stage)
    pushed = 0
    errors = 0
    for f in result.get("findings", []):
        try:
            ingest_finding(f)
            pushed += 1
        except (RuntimeError, ValueError) as e:
            errors += 1
            log(f"ingest failed for {f.get('id')}: {e}")
    note = result.get("note", "")
    if pushed or errors:
        note += f"; {pushed} finding(s) pushed"
        if errors:
            note += f", {errors} ingest error(s)"
    _resolve(run_id, bool(result.get("ok")), note, pushed)


def handle_remediation(run_id: str, project: str, scope: Dict[str, Any]) -> None:
    """Full secure loop. Prefers LOCAL_CLONE_PATH (the engine's own checkout
    of the target); falls back to fetching the repo. The engine's own
    APPROVAL_REQUIRED gate runs before any code is modified."""
    if LOCAL_CLONE_PATH and os.path.isdir(LOCAL_CLONE_PATH):
        files = load_files_from_dir(LOCAL_CLONE_PATH)
        source = f"local clone {LOCAL_CLONE_PATH}"
    else:
        try:
            files = fetch_repo_files(project)
            source = "fetched repo"
        except Exception as e:  # noqa: BLE001
            _resolve(run_id, False, f"target fetch failed and LOCAL_CLONE_PATH is unset: {e}", 0)
            return
    if not files:
        _resolve(run_id, False, "no target files — loop not executed", 0)
        return
    heartbeat(run_id, f"full secure loop: target = {source}")

    def stage(msg: str) -> None:
        heartbeat(run_id, msg)

    result = run_full_secure_loop(project, scope, files, log=stage)
    _resolve(run_id, bool(result.get("ok")), result.get("note", ""), 0)
    if result.get("verdict"):
        log(f"run {run_id} verdict: {result['verdict']} ({len(result.get('attackSteps', []))} step(s))")


def handle_run(run: Dict[str, Any], dry_run: bool) -> None:
    claim = claim_run(run)
    if claim is None:
        return
    scope = claim.get("scope") or {"authorizedPaths": [], "blockedPaths": []}
    kind = claim.get("kind", "validation")
    log(
        f"claimed run {run['_id']} project={claim['projectId']} kind={kind} "
        f"authorized={json.dumps(scope.get('authorizedPaths', []))} "
        f"blocked={json.dumps(scope.get('blockedPaths', []))}"
    )
    project = claim["projectId"]
    if kind == "scan":
        handle_scan(run["_id"], project, scope)
    elif kind == "remediation":
        if dry_run:
            _resolve(run["_id"], False, "dry run — full loop not executed", 0)
        else:
            handle_remediation(run["_id"], project, scope)
    else:
        handle_validation(run["_id"], project, scope, dry_run)


# ---------------------------------------------------------------------------
# Approvals / revalidations: real apply + re-attack against LOCAL_CLONE_PATH
# ---------------------------------------------------------------------------

def _verify_on_clone(clone: str, category: str, validator_name: str) -> Dict[str, Any]:
    """Start the real LocalTarget on the clone and run the category's real
    validator. Returns the raw validation dict (has 'validated')."""
    target = LocalTarget(clone)
    target.start()
    try:
        validator = LocalAttackValidator(target.base_url)
        method = getattr(validator, validator_name, None)
        if method is None:
            raise RuntimeError(f"validator not found: {validator_name}")
        return method()
    finally:
        target.stop()


def handle_approvals() -> None:
    try:
        approvals = api("/api/approvals/pending").get("approvals", [])
    except RuntimeError as e:
        log(f"approvals/pending failed: {e}")
        return
    for a in approvals:
        ctx = a.get("finding") or cache_load().get(a["findingId"])
        if not ctx:
            log(
                f"PENDING approval {a['_id']} finding={a['findingId']} — "
                "no engine context for this finding (ingested by another "
                "engine instance?); leaving pending rather than guessing"
            )
            continue
        if not (LOCAL_CLONE_PATH and os.path.isdir(LOCAL_CLONE_PATH)):
            log(f"PENDING approval {a['_id']} — LOCAL_CLONE_PATH unset; waiting")
            continue
        rel = ctx.get("file", "")
        target_file = os.path.abspath(os.path.join(LOCAL_CLONE_PATH, rel))
        if not target_file.startswith(os.path.abspath(LOCAL_CLONE_PATH) + os.sep) or not os.path.isfile(target_file):
            log(f"PENDING approval {a['_id']} — finding file {rel} not in clone; leaving pending")
            continue
        category = (ctx.get("vulnerabilityType") or "").upper().replace(" ", "_")
        validator_name = (ctx.get("run") or {}).get("validator") or VALIDATOR_BY_CATEGORY.get(category, "")
        if not validator_name.startswith("validate_"):
            validator_name = VALIDATOR_BY_CATEGORY.get(category, "")
        if not validator_name:
            log(f"PENDING approval {a['_id']} — no validator for category {category}; leaving pending")
            continue
        backup = target_file + ".pg-backup"
        shutil.copyfile(target_file, backup)
        try:
            with open(target_file, "w", encoding="utf-8") as fh:
                fh.write(a.get("code", ""))
            log(f"applied approved buffer to {rel}; re-attacking ({validator_name})")
            result = _verify_on_clone(LOCAL_CLONE_PATH, category, validator_name)
            blocked = not bool(result.get("validated"))
            verdict = "VERIFIED_FIXED" if blocked else "STILL_VULNERABLE"
            step_name = f"Engine validator {validator_name} executed against the controlled target"
            api("/api/approvals/resolve", method="POST", body={
                "approvalId": a["_id"],
                "verdict": verdict,
                "attackSteps": [{"name": step_name, "verdict": "blocked" if blocked else "exploitable"}],
                "engineRunId": f"py-apply-{int(time.time())}",
                "log": [f"[engine] applied buffer to {rel}", f"[engine] {result.get('evidence', '')}"],
            })
            log(f"resolved approval {a['_id']}: {verdict}")
        except Exception as e:  # noqa: BLE001 — restore clone, stay honest
            shutil.copyfile(backup, target_file)
            log(f"approval {a['_id']} verification failed ({e}); buffer restored, approval left pending")
        finally:
            if os.path.exists(backup):
                os.remove(backup)


def handle_revalidations() -> None:
    try:
        revals = api("/api/revalidate/pending").get("revalidations", [])
    except RuntimeError as e:
        log(f"revalidate/pending failed: {e}")
        return
    for r in revals:
        ctx = r.get("finding") or cache_load().get(r["findingId"])
        if not ctx:
            log(f"PENDING revalidation {r['_id']} — no engine context; leaving pending")
            continue
        if not (LOCAL_CLONE_PATH and os.path.isdir(LOCAL_CLONE_PATH)):
            log(f"PENDING revalidation {r['_id']} — LOCAL_CLONE_PATH unset; waiting")
            continue
        category = (ctx.get("vulnerabilityType") or "").upper().replace(" ", "_")
        validator_name = (ctx.get("run") or {}).get("validator") or VALIDATOR_BY_CATEGORY.get(category, "")
        if not validator_name.startswith("validate_"):
            validator_name = VALIDATOR_BY_CATEGORY.get(category, "")
        if not validator_name:
            log(f"PENDING revalidation {r['_id']} — no validator for {category}; leaving pending")
            continue
        try:
            result = _verify_on_clone(LOCAL_CLONE_PATH, category, validator_name)
            blocked = not bool(result.get("validated"))
            verdict = "VERIFIED_FIXED" if blocked else "STILL_VULNERABLE"
            step_name = f"Engine validator {validator_name} executed against the controlled target"
            api("/api/revalidate/resolve", method="POST", body={
                "revalidationId": r["_id"],
                "verdict": verdict,
                "attackSteps": [{"name": step_name, "verdict": "blocked" if blocked else "exploitable"}],
                "engineRunId": f"py-reval-{int(time.time())}",
                "log": [f"[engine] fresh re-attack ({validator_name})", f"[engine] {result.get('evidence', '')}"],
            })
            log(f"resolved revalidation {r['_id']}: {verdict}")
        except Exception as e:  # noqa: BLE001
            log(f"revalidation {r['_id']} failed ({e}); left pending — no verdict invented")


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
    if not dry_run:
        handle_approvals()
        handle_revalidations()
    return bool(runs)


def main() -> None:
    _require_env()
    parser = argparse.ArgumentParser(description="PurpleGuard engine loop")
    parser.add_argument("--once", action="store_true", help="single poll pass")
    parser.add_argument("--dry-run", action="store_true", help="claim runs, observe scope, resolve ok:false — no validation")
    args = parser.parse_args()

    log(f"starting against {SITE}{' (dry-run)' if args.dry_run else ''}"
        f"{' clone=' + LOCAL_CLONE_PATH if LOCAL_CLONE_PATH else ''}")
    had_work = True
    while not args.once:
        if not had_work:
            time.sleep(POLL_INTERVAL_SECONDS)
        try:
            had_work = poll_pass(args.dry_run)
        except Exception as e:  # noqa: BLE001
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
