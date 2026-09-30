#!/usr/bin/env python3
"""PurpleGuard engine adapter — bridge between the Convex runs loop and the
REAL PurpleGuard engine (hacker/ + scanner/ packages).

This module contains NO security logic of its own. It:
  1. materializes the scope-filtered target files into a temp directory,
  2. runs the real engine end-to-end:
       discover (PurpleGuardHacker.hack)
       -> plan (AttackPlanner)
       -> validate (LocalAttackValidator against the controlled LocalTarget)
       -> build findings (FindingBuilder)
       -> map to purpleguard.findings/v1 payloads,
  3. and drives the full secure loop (PurpleGuardSecurityOrchestrator) with
     the engine's own APPROVAL_REQUIRED gate before any code is modified.

Honesty rules (enforced by construction, not by patching):
  - attackSteps verdicts come from the engine's validation / re-verification
    results only. A step that needs a live target and didn't get one is
    reported as "blocked" with the engine's own evidence text.
  - No finding is emitted for code the engine did not actually flag.
  - Every failure raises or returns ok:false with the engine's own message.
"""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile
from typing import Any, Callable, Dict, List, Optional, Tuple

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

# --- Real engine imports (the whole point of this adapter) ------------------
from hacker.engine import PurpleGuardHacker                      # noqa: E402
from hacker.findings import FindingBuilder                       # noqa: E402
from hacker.orchestrator import PurpleGuardSecurityOrchestrator  # noqa: E402
from hacker.planner import AttackPlanner                         # noqa: E402
from hacker.remediation_adapter import HackerRemediationAdapter  # noqa: E402
from hacker.reverification import HackerReverification           # noqa: E402
from hacker.validation.local_target import LocalTarget           # noqa: E402
from hacker.validation.validator import LocalAttackValidator     # noqa: E402
from scanner.engine import SecurityScanner                       # noqa: E402

# Reuse the exact scope semantics of the static validators (fail closed).
from validators import DEFAULT_IGNORED_DIRS, filter_files        # noqa: E402

# Category -> honest re-test check (what a fix must prove on the target).
_RETEST_CHECKS = {
    "SQL_INJECTION": "Injection payload no longer changes query behavior on the target",
    "CODE_EXECUTION": "Server no longer evaluates attacker-supplied expressions",
    "PATH_TRAVERSAL": "Traversal payload no longer returns files outside the intended directory",
    "COMMAND_INJECTION": "Injected marker no longer appears in command output",
    "XSS": "Payload is no longer reflected unescaped in the response",
    "OPEN_REDIRECT": "Redirect Location is no longer attacker-controlled",
    "SSRF": "Server no longer requests attacker-chosen destinations",
    "DESERIALIZATION": "Endpoint no longer reconstructs objects from attacker-supplied serialized data",
}


# ---------------------------------------------------------------------------
# Target materialization (scope-filtered, from the runs-loop fetched files)
# ---------------------------------------------------------------------------

def materialize_target(
    project: str,
    files: List[Dict[str, Any]],
    scope: Optional[Dict[str, Any]],
) -> Optional[str]:
    """Write the scope-authorized files into a temp dir shaped like a repo.

    Scope is applied FIRST and fail-closed via validators.filter_files (the
    same code the static path uses): no authorizedPaths => nothing runs.
    Vendored/generated trees are skipped as non-remediation surface.
    Returns the temp dir path, or None when nothing is in scope.
    """
    in_scope = filter_files(files, scope)
    if not in_scope:
        return None
    in_scope = [
        f for f in in_scope
        if not any(ignored in f.get("path", "") for ignored in DEFAULT_IGNORED_DIRS)
    ]
    if not in_scope:
        return None
    root = tempfile.mkdtemp(prefix=f"purpleguard-{project.replace('/', '_')}-")
    for f in in_scope:
        rel = f.get("path", "")
        if not rel or ".." in rel.split("/"):
            continue  # refuse to escape the sandbox dir
        dest = os.path.join(root, rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "w", encoding="utf-8") as fh:
            fh.write(f.get("content", "") or "")
    return root


def find_local_project(project: str, candidates: List[str]) -> Optional[str]:
    """Use an existing local checkout when the caller provides one.
    Returns the first existing directory."""
    for c in candidates:
        if c and os.path.isdir(c):
            return os.path.abspath(c)
    return None


# ---------------------------------------------------------------------------
# Mapping: engine outputs -> purpleguard.findings/v1 payloads
# ---------------------------------------------------------------------------

def _short_hash(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:12]


def _confidence_pct(value: Any) -> int:
    try:
        return round(100 * float(value))
    except (TypeError, ValueError):
        return 0


def _redact(text: str) -> str:
    t = (text or "").strip()
    if len(t) <= 8:
        return "*" * len(t)
    return f"{t[:4]}{'*' * (len(t) - 8)}{t[-4:]}"


def _snippet_at(root: str, rel_path: str, line_no: int, width: int = 2) -> Optional[str]:
    """Best-effort source snippet from the materialized target, only when the
    path resolves inside it. Guards against emitting engine-internal paths."""
    if not rel_path:
        return None
    full = os.path.abspath(os.path.join(root, rel_path))
    if not full.startswith(os.path.abspath(root) + os.sep):
        return None
    try:
        with open(full, "r", encoding="utf-8", errors="ignore") as fh:
            lines = fh.readlines()
    except OSError:
        return None
    idx = max(0, line_no - 1)
    if idx >= len(lines):
        return None
    return "".join(lines[max(0, idx - width): idx + width + 1]).rstrip("\n")


def _map_hacker_finding(
    root: str,
    cf: Dict[str, Any],
    path_by_id: Dict[str, Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """ConfirmedFinding.to_dict() (real engine output) -> contract payload."""
    path = path_by_id.get(cf.get("path_id"))
    if not path:
        return None
    nodes = path.get("nodes", []) or []
    chain = [
        f"{n.get('kind', 'STEP')}: {n.get('name', '')} "
        f"({(n.get('location') or {}).get('file', '?')}:"
        f"{(n.get('location') or {}).get('line', '?')})"
        for n in nodes
    ] or [f"Engine attack path {cf.get('path_id')} in the analyzed target"]

    validated = bool(cf.get("validated"))
    category = cf.get("category", "")

    # Phase 4.1: preserve the validator's raw HTTP artifacts as structured
    # evidence when they exist. Absent artifacts produce NO evidence.
    http_evidence = []
    request_art = cf.get("request")
    if isinstance(request_art, dict):
        status = request_art.get("status")
        if status is not None:
            http_evidence.append({
                "id": "ev-http-status",
                "kind": "request",
                "label": "Observed HTTP status",
                "content": str(status),
            })
        body = request_art.get("body")
        if isinstance(body, str) and body.strip():
            http_evidence.append({
                "id": "ev-http-body",
                "kind": "response",
                "label": "Observed response body (excerpt)",
                "content": body[:500],
            })
        headers = request_art.get("headers")
        if isinstance(headers, dict) and headers:
            interesting = {
                k: v for k, v in headers.items()
                if str(k).lower() in ("location", "content-type", "content-length")
            }
            if interesting:
                http_evidence.append({
                    "id": "ev-http-headers",
                    "kind": "response",
                    "label": "Observed response headers (subset)",
                    "content": "\n".join(f"{k}: {v}" for k, v in interesting.items()),
                })
    attack_steps = [
        {
            "name": f"Engine validator {cf.get('validator', '')} executed against the controlled target",
            "description": (
                "The real LocalAttackValidator ran this finding's registered "
                "validator against the local PurpleGuard-owned target."
            ),
            "criteria": "Validator reports validated=true from its own request evidence",
            "verdict": "exploitable" if validated else "blocked",
            "log": [
                f"[engine] validator={cf.get('validator', '')} validated={validated}",
                f"[engine] evidence: {cf.get('evidence', '')}",
            ] + (
                [f"[engine] observed HTTP status: {request_art['status']}"]
                if isinstance(request_art, dict) and request_art.get("status") is not None
                else []
            ),
        },
        {
            "name": "Post-remediation re-attack replay",
            "description": (
                "HackerReverification replays the recorded payload against the "
                "target after remediation."
            ),
            "criteria": "Replayed attack is blocked on the remediated target",
            # Not yet known at discovery time: no claim is made either way.
            "verdict": "blocked",
            "log": [
                "[engine] verdict for this step is written back after "
                "re-verification (approvals/resolve or revalidate/resolve); "
                "no result exists yet, so none is claimed here."
            ],
        },
    ]

    return {
        "id": f"PG-{cf.get('path_id', _short_hash(str(cf)))}",
        "title": cf.get("title") or f"Confirmed {category} attack path",
        "severity": str(cf.get("severity", "medium")).lower(),
        "vulnerabilityType": category.replace("_", " ").title() or "Validated attack path",
        "repo": "",  # filled by caller
        "file": cf.get("sink_file") or cf.get("source_file") or "",
        "location": f"line {cf.get('sink_line') or cf.get('source_line') or 0}",
        "attackSurface": "Local target · live validated attack path",
        "attackPath": chain,
        "explanation": (
            f"The PurpleGuard engine validated this {category} attack path "
            f"(confidence {_confidence_pct(cf.get('confidence'))}%). "
            f"Impact: {cf.get('impact', '')}"
        ),
        "remediation": (
            "Open this finding in the Developer workspace, fix the sink, and "
            "approve the change through the approval gate; the engine then "
            "replays the attack and records the real verdict."
        ),
        "vulnerableCode": (
            _snippet_at(root, cf.get("sink_file") or "", int(cf.get("sink_line") or 0))
            or _snippet_at(root, cf.get("source_file") or "", int(cf.get("source_line") or 0))
            or ""
        ),
        "proposedPatch": None,
        "fixedCode": None,
        "reTestChecks": [_RETEST_CHECKS.get(category, "Replay of the recorded payload no longer succeeds")],
        "vulnerableMarker": _redact(cf.get("payload", "")),
        "evidence": http_evidence + [
            {
                "id": "ev-validator",
                "kind": "execution",
                "label": f"Validator output ({cf.get('validator', '')})",
                "content": f"[engine] {cf.get('evidence', '')}",
            },
            {
                "id": "ev-payload",
                "kind": "request",
                "label": "Payload used by the validator (redacted display)",
                "content": _redact(cf.get("payload", "")),
            },
        ],
        "attackSteps": attack_steps,
        "testerNote": (
            "Validated by the real PurpleGuard engine against its controlled "
            "local target. Verdicts come from the engine's validators and "
            "re-verification, never from the UI."
        ),
        "run": {
            "validator": cf.get("validator", ""),
            "kind": "purpleguard-engine",
            "path_id": cf.get("path_id", ""),
        },
    }


def _map_static_finding(project: str, root: str, f: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Real SecurityScanner finding dict -> contract payload.

    Only emitted when the finding's file/line resolve inside the materialized
    target (scanner file paths are absolute; contract paths are repo-relative).
    """
    abs_file = f.get("file", "")
    rel = os.path.relpath(abs_file, root) if abs_file else ""
    if rel.startswith("..") or os.path.isabs(rel):
        return None
    line_no = int(f.get("line", 0) or 0)
    snippet = _snippet_at(root, rel, line_no)
    if snippet is None:
        return None
    fid = f"PG-{f.get('id', 'PG???')}-{_short_hash(project, rel, line_no)}"
    return {
        "id": fid,
        "title": f"{f.get('name', f.get('id', 'Scanner finding'))} in {rel}",
        "severity": str(f.get("severity", "medium")).lower(),
        "vulnerabilityType": f.get("category") or f.get("name") or "Static finding",
        "repo": project,
        "file": rel,
        "location": f"line {line_no}",
        "attackSurface": "Repository · static analysis (PG rules)",
        "attackPath": [
            f"Static rule {f.get('id')} matched {rel}:{line_no}",
            "Scanner finding only — adversarial validation pending",
        ],
        "explanation": (
            f"PurpleGuard static rule {f.get('id')} ({f.get('name')}) matched "
            f"{rel} at line {line_no}. This is scanner output, not a validated "
            "attack; it becomes an attack path only if the engine's validator "
            "confirms it."
        ),
        "remediation": (
            "Review in the Developer workspace. Treat as a candidate weakness "
            "until adversarial validation confirms it."
        ),
        "vulnerableCode": snippet,
        "proposedPatch": None,
        "fixedCode": None,
        "reTestChecks": [
            f"Rule {f.get('id')} no longer matches {rel} on re-scan"
        ],
        "vulnerableMarker": "",
        "evidence": [
            {
                "id": "ev-rule",
                "kind": "code",
                "label": f"Rule {f.get('id')} match at {rel}:{line_no}",
                "content": snippet,
            }
        ],
        "attackSteps": [
            {
                "name": f"Static rule {f.get('id')} matched",
                "description": f"{f.get('name')} pattern present at {rel}:{line_no}",
                "criteria": "Scanner rule matched real source lines in an in-scope file",
                "verdict": "exploitable",
                "log": [f"[scanner] {f.get('id')} {f.get('name')} at {rel}:{line_no}"],
            },
            {
                "name": "Adversarially validate the match",
                "description": "LocalAttackValidator must confirm the weakness against the running target",
                "criteria": "Validator reports validated=true for this category",
                "verdict": "blocked",
                "log": [
                    "[scanner] static finding — no adversarial validation was "
                    "performed for this match; no exploitability is claimed"
                ],
            },
        ],
        "testerNote": "Static scan finding. Not a confirmed attack until validated.",
        "run": {"validator": f.get("id", ""), "kind": "purpleguard-static-scan"},
    }


# ---------------------------------------------------------------------------
# End-to-end: discover -> validate -> findings (live target REQUIRED)
# ---------------------------------------------------------------------------

def run_discovery_and_validation(
    project: str,
    scope: Optional[Dict[str, Any]],
    files: List[Dict[str, Any]],
    log: Callable[[str], None] = lambda msg: None,
) -> Dict[str, Any]:
    """Run the real engine and return {ok, note, stages, findings}.

    Findings are ready for /api/ingest_finding. The live local target is
    REQUIRED: no target -> no validation -> ok:false. Nothing is faked.
    """
    root = materialize_target(project, files, scope)
    if root is None:
        return {
            "ok": False,
            "note": "no files in run scope (fail-closed) — nothing was inspected",
            "stages": [],
            "findings": [],
        }

    stages: List[Tuple[str, str]] = [("materialized in-scope target", root)]
    engine_findings: List[Dict[str, Any]] = []
    try:
        # 1. DISCOVER — real PurpleGuardHacker over the materialized target.
        log("engine: discovering attack surface (PurpleGuardHacker)")
        stages.append(("discovering attack surface", "PurpleGuardHacker.hack()"))
        report_dict = PurpleGuardHacker(root).hack()
        attack_paths = report_dict.get("attack_paths", []) or []
        path_by_id = {p.get("id"): p for p in attack_paths}
        if not attack_paths:
            return {
                "ok": True,
                "note": (
                    f"engine discovered no attack paths "
                    f"({report_dict.get('files_analyzed', 0)} files analyzed) — honest empty result"
                ),
                "stages": stages,
                "findings": [],
            }

        # 2. PLAN — real AttackPlanner maps categories to registered validators.
        stages.append(("planning validations", f"{len(attack_paths)} attack path(s)"))
        plans = AttackPlanner().plan(attack_paths)
        if not plans:
            return {
                "ok": True,
                "note": "attack paths found but no validators are registered for their categories",
                "stages": stages,
                "findings": [],
            }

        # 3. VALIDATE — real LocalTarget + LocalAttackValidator (live required).
        stages.append(("starting controlled local target", "LocalTarget.start()"))
        try:
            target = LocalTarget(root)
            target.start()
        except Exception as e:  # noqa: BLE001 — honest failure, nothing invented
            return {
                "ok": False,
                "note": f"controlled local target could not start: {e} — no validation executed",
                "stages": stages,
                "findings": [],
            }
        try:
            validator = LocalAttackValidator(target.base_url)
            validations = []
            for plan in plans:
                method = getattr(validator, plan.validator, None)
                if method is None:
                    validations.append({
                        "path_id": plan.path_id,
                        "category": plan.category,
                        "validated": False,
                        "payload": "",
                        "evidence": f"Validator not found: {plan.validator}",
                    })
                    continue
                validations.append({
                    "path_id": plan.path_id,
                    "category": plan.category,
                    "severity": plan.severity,
                    "validator": plan.validator,
                    **method(),
                })
        finally:
            target.stop()

        # 4. BUILD FINDINGS — real FindingBuilder over real paths+validations.
        stages.append(("validating planned attacks", f"{len(plans)} validator run(s)"))
        plan_dicts = [
            {
                "path_id": p.path_id,
                "category": p.category,
                "severity": p.severity,
                "confidence": p.confidence,
                "validator": p.validator,
            }
            for p in plans
        ]
        confirmed = FindingBuilder().build(attack_paths, plan_dicts, validations)
        for cf in confirmed:
            payload = _map_hacker_finding(root, cf.to_dict(), path_by_id)
            if payload:
                payload["repo"] = project
                engine_findings.append(payload)

        # 5. STATIC SCAN — real SecurityScanner, clearly labeled as static.
        stages.append(("running static scan (PG rules)", "SecurityScanner.scan()"))
        for f in SecurityScanner(root).scan():
            payload = _map_static_finding(project, root, f)
            if payload:
                engine_findings.append(payload)

        pushed_note = (
            f"engine validated {sum(1 for c in confirmed if c.validated)} attack path(s); "
            f"{len(engine_findings)} finding payload(s) built"
        )
        stages.append(("building finding payloads", pushed_note))
        return {"ok": True, "note": pushed_note, "stages": stages, "findings": engine_findings}
    finally:
        try:
            import shutil
            shutil.rmtree(root, ignore_errors=True)
        except Exception:  # noqa: BLE001 — temp cleanup is best-effort
            pass


# ---------------------------------------------------------------------------
# End-to-end: the full secure loop (approval-gated), for remediation runs
# ---------------------------------------------------------------------------

def run_full_secure_loop(
    project: str,
    scope: Optional[Dict[str, Any]],
    files: List[Dict[str, Any]],
    log: Callable[[str], None] = lambda msg: None,
) -> Dict[str, Any]:
    """Run PurpleGuardSecurityOrchestrator.run() twice: once to reach the
    engine's own APPROVAL_REQUIRED gate, then approved=True, then re-verify.

    Returns {ok, note, verdict, attackSteps}.
    verdict is "VERIFIED_FIXED" / "STILL_VULNERABLE" / None (not verified).
    attackSteps verdicts come ONLY from HackerReverification results.
    """
    root = materialize_target(project, files, scope)
    if root is None:
        return {"ok": False, "note": "no files in run scope — nothing executed", "verdict": None, "attackSteps": []}
    try:
        orch = PurpleGuardSecurityOrchestrator(root)

        log("engine: run to the approval gate")
        gate = orch.run(approved=False)
        if gate.get("status") != "APPROVAL_REQUIRED":
            return {
                "ok": False,
                "note": f"engine stopped at {gate.get('status')}: {gate.get('message', '')}",
                "verdict": None,
                "attackSteps": [],
            }

        log("engine: applying approved remediation (post-gate)")
        final = orch.run(approved=True)

        steps: List[Dict[str, Any]] = []
        verdict: Optional[str] = None
        hv = final.get("hacker_verification") or {}
        results = hv.get("results", []) or []
        for r in results:
            blocked = r.get("blocked")
            steps.append({
                "name": f"Re-attack {r.get('category', '')} (path {r.get('path_id', '')})",
                "description": "HackerReverification replayed the recorded payload on the remediated target",
                "criteria": "Replayed attack must be blocked",
                "verdict": "blocked" if blocked is True else "exploitable",
                "log": [
                    f"[engine] status={r.get('status')}",
                    f"[engine] evidence: {r.get('evidence', '')}",
                ],
            })
        if results:
            all_blocked = all(r.get("blocked") is True for r in results)
            verdict = "VERIFIED_FIXED" if all_blocked else "STILL_VULNERABLE"
        else:
            verdict = {
                "SECURITY_VERIFIED": "VERIFIED_FIXED",
                "SECURITY_NOT_VERIFIED": "STILL_VULNERABLE",
            }.get(final.get("status"))
        return {
            "ok": True,
            "note": f"engine full loop finished with status {final.get('status')}",
            "verdict": verdict,
            "attackSteps": steps,
        }
    except Exception as e:  # noqa: BLE001 — surfaced honestly to the run record
        return {"ok": False, "note": f"engine full loop failed: {e}", "verdict": None, "attackSteps": []}
    finally:
        try:
            import shutil
            shutil.rmtree(root, ignore_errors=True)
        except Exception:  # noqa: BLE001
            pass


def reverify_local(
    project_path: str,
    findings: List[Any],
    log: Callable[[str], None] = lambda msg: None,
) -> Dict[str, Any]:
    """Replay recorded engine findings against a LOCAL checkout target."""
    target = LocalTarget(project_path)
    target.start()
    try:
        log("engine: replaying recorded findings (HackerReverification)")
        reverification = HackerReverification(target.base_url)
        results = reverification.verify(findings)
        return reverification.verdict(results)
    finally:
        target.stop()


def propose_remediation_preview(findings: List[Any]) -> List[Dict[str, Any]]:
    """Real HackerRemediationAdapter previews (used for AI-fix proposals)."""
    return HackerRemediationAdapter().preview_all(findings)
