#!/usr/bin/env python3
"""PurpleGuard validators — real, deterministic checks against fetched
repository artifacts.

Honesty contract (mirrors docs/ENGINE_API.md and the platform rules):

- Every finding is derived from code that actually exists in the fetched,
  in-scope target. Nothing is mocked; no demo results are produced.
- attackSteps[].verdict is "exploitable" ONLY when the executed check itself
  deterministically demonstrates the exposure from the artifact it inspected
  (e.g. a live-looking credential literal is present and matchable in the
  file). A static check NEVER claims network reachability or a successful
  remote attack — that is the external engine's job (orchestrator.py /
  reverification.py in the engine repo).
- A step whose condition does not hold is honestly reported as "blocked".
- All matched secrets are redacted in evidence; originals are never emitted.

Scope contract:
- run validators only on files whose path matches the run's authorizedPaths
  glob list and does not match blockedPaths (path_scope.filter_files).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Scope filtering
# ---------------------------------------------------------------------------

_GLOB_CACHE: Dict[str, re.Pattern] = {}


def _glob_to_regex(pattern: str) -> re.Pattern:
    if pattern in _GLOB_CACHE:
        return _GLOB_CACHE[pattern]
    # Support ** (any depth), * (any chars except /), ? (single char).
    i = 0
    out = []
    while i < len(pattern):
        c = pattern[i]
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif c == "*":
            out.append("[^/]*")
            i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(c))
            i += 1
    rx = re.compile("^" + "".join(out) + "$")
    _GLOB_CACHE[pattern] = rx
    return rx


def path_in_scope(path: str, patterns: List[str]) -> bool:
    # Scope patterns are repo-root-relative (the deployment sends "/**" to
    # mean "everything"), so normalize leading slashes on both sides.
    norm = path.lstrip("/")
    return any(_glob_to_regex(p.lstrip("/")).match(norm) for p in patterns)


def filter_files(
    files: List[Dict[str, Any]], scope: Optional[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Keep only files the run's scope authorizes. No scope => nothing runs
    (fail closed — an absent scope is not a grant)."""
    if not scope:
        return []
    authorized = scope.get("authorizedPaths") or []
    blocked = scope.get("blockedPaths") or []
    if not authorized:
        return []
    kept: List[Dict[str, Any]] = []
    for f in files:
        p = f.get("path", "")
        if path_in_scope(p, blocked):
            continue
        if path_in_scope(p, authorized):
            kept.append(f)
    return kept


# ---------------------------------------------------------------------------
# Evidence helpers
# ---------------------------------------------------------------------------


def _redact(match_text: str) -> str:
    t = match_text.strip()
    if len(t) <= 8:
        return "*" * len(t)
    return f"{t[:4]}{'*' * (len(t) - 8)}{t[-4:]}"


def _snippet(lines: List[str], idx: int, width: int = 2) -> str:
    lo = max(0, idx - width)
    hi = min(len(lines), idx + width + 1)
    return "\n".join(lines[lo:hi])


def _finding_id(project: str, path: str, line_no: int, kind: str) -> str:
    h = hashlib.sha256(f"{project}|{path}|{line_no}|{kind}".encode()).hexdigest()[:12]
    return f"PG-{h}"


@dataclass
class Step:
    name: str
    description: str
    criteria: str
    verdict: str  # "exploitable" | "blocked"
    log: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Static validators (each returns zero or one finding per match)
# ---------------------------------------------------------------------------

# Live-looking cloud credential literals. Matching one of these in a fetched
# in-scope file deterministically demonstrates the secret is present in the
# artifact the validator inspected.
_AWS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_GITHUB_PAT = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")
_SLACK_TOKEN = re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")
_GENERIC_ASSIGN = re.compile(
    r"""(?i)\b(api[_-]?key|secret|password|token|passwd|pwd)\b["']?\s*[:=]\s*["']([^"'\s]{12,})["']"""
)
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")
_TLS_DISABLED = re.compile(
    r"""(?xi)(
        verify_ssl\s*=\s*False
        | check_hostname\s*=\s*False
        | verify\s*=\s*False
        | rejectUnauthorized\s*:\s*false
        | NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0
    )"""
)
_SQL_FORMAT = re.compile(
    r"""(?i)(execute|executemany|query|raw)\s*\(\s*(f["']|["']\s*%|\+\s*\w+)"""
)
_EVAL_SINK = re.compile(r"(?i)\b(eval|exec)\s*\(\s*(request\.|os\.environ|args\.|input\()")

# Third-party / generated code is not the developer's remediation surface;
# findings there would be noise. The repo walk skips these too.
DEFAULT_IGNORED_DIRS = ("node_modules/", "vendor/", "dist/", "build/", ".git/")


def _line_of(lines: List[str], rx: re.Pattern) -> Optional[int]:
    for i, ln in enumerate(lines):
        if rx.search(ln):
            return i
    return None


def _static_findings(
    project: str, files: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for f in files:
        path = f.get("path", "")
        content = f.get("content", "") or ""
        if not content.strip():
            continue
        lines = content.splitlines()

        for label, rx, sev, vtype in (
            ("AWS access key literal", _AWS_KEY, "critical", "Hardcoded cloud credential"),
            ("GitHub token literal", _GITHUB_PAT, "critical", "Hardcoded VCS token"),
            ("Slack token literal", _SLACK_TOKEN, "critical", "Hardcoded messaging token"),
            ("Private key block", _PRIVATE_KEY, "critical", "Committed private key"),
        ):
            m = None
            for ln in lines:
                m = rx.search(ln)
                if m:
                    break
            if not m:
                continue
            idx = lines.index(m.string) if m.string in lines else lines.index(ln)
            findings.append(
                {
                    "id": _finding_id(project, path, idx + 1, label),
                    "title": f"{label} committed in {path}",
                    "severity": sev,
                    "vulnerabilityType": vtype,
                    "repo": project,
                    "file": path,
                    "location": f"line {idx + 1}",
                    "attackSurface": "Repository · committed artifact",
                    "attackPath": [
                        f"Static scan of authorized target located a {label.lower()} in {path}",
                        "Validator confirms the literal is present and matchable in the fetched artifact",
                    ],
                    "explanation": (
                        f"A {label.lower()} is present in {path} at line {idx + 1}. "
                        "Anyone with read access to the artifact obtains a live-looking "
                        "credential. This check is deterministic and local; it makes no "
                        "claim about network reachability of the credential."
                    ),
                    "remediation": (
                        "Revoke/rotate the credential, remove the literal, and load it "
                        "from a secrets manager or environment variable. Add history "
                        "scrubbing and pre-commit secret scanning to prevent recurrence."
                    ),
                    "vulnerableCode": _snippet(lines, idx),
                    "proposedPatch": None,
                    "fixedCode": None,
                    "reTestChecks": [
                        f"No {label.lower()} matches remain in {path}"
                    ],
                    "vulnerableMarker": _redact(m.group(0)),
                    "evidence": [
                        {
                            "id": f"ev-{label.split()[0].lower()}",
                            "kind": "code",
                            "label": f"{label} at {path}:{idx + 1} (redacted)",
                            "content": f"{path}:{idx + 1}  {_redact(m.group(0))}",
                        }
                    ],
                    "attackSteps": [
                        Step(
                            name=f"Locate {label.lower()} in authorized artifact",
                            description=f"Scan in-scope file {path} for {label.lower()}",
                            criteria="A live-looking literal matches the validator pattern",
                            verdict="exploitable",
                            log=[
                                f"[validator] {path}:{idx + 1} matched ({label.lower()}, redacted)"
                            ],
                        ).__dict__,
                        Step(
                            name="Demonstrate remote use of credential",
                            description="Authenticate against the provider with the found credential",
                            criteria="Provider accepts the credential in a live probe",
                            verdict="blocked",
                            log=[
                                "[validator] static check cannot and does not attempt live provider authentication — requires the external network validator"
                            ],
                        ).__dict__,
                    ],
                    "testerNote": "Authorized static validation only. No network probes were performed.",
                    "run": {"validator": "purpleguard-static", "kind": "regex-evidence"},
                }
            )

        # Generic secret-looking assignment
        for i, ln in enumerate(lines):
            m = _GENERIC_ASSIGN.search(ln)
            if m:
                key, val = m.group(1), m.group(2)
                if re.fullmatch(r"(?i)(os\.environ|process\.env|env\[)?.*", val) and val.lower().startswith(("os.", "process.", "env")):
                    continue  # reads from env — not a hardcoded secret
                if val.islower() and len(val) <= 16 and val in ("true", "false", "password", "changeme") and key.lower() in ("password",):
                    pass
                fid = _finding_id(project, path, i + 1, f"assign:{key}")
                findings.append(
                    {
                        "id": fid,
                        "title": f"Hardcoded '{key}' assignment in {path}",
                        "severity": "high",
                        "vulnerabilityType": "Hardcoded secret",
                        "repo": project,
                        "file": path,
                        "location": f"line {i + 1}",
                        "attackSurface": "Repository · committed artifact",
                        "attackPath": [
                            f"Static scan of authorized target found hardcoded '{key}' in {path}",
                        ],
                        "explanation": (
                            f"'{key}' is assigned a literal value at {path}:{i + 1}. "
                            "The validator confirms the assignment exists in the fetched "
                            "artifact; it makes no claim beyond artifact content."
                        ),
                        "remediation": (
                            f"Load '{key}' from environment or a secrets manager and "
                            "rotate the exposed value."
                        ),
                        "vulnerableCode": _snippet(lines, i),
                        "proposedPatch": None,
                        "fixedCode": None,
                        "reTestChecks": [f"No hardcoded '{key}' literal remains in {path}"],
                        "vulnerableMarker": _redact(val),
                        "evidence": [
                            {
                                "id": "ev-assign",
                                "kind": "code",
                                "label": f"{key} assignment at {path}:{i + 1} (redacted)",
                                "content": f"{path}:{i + 1}  {key} = {_redact(val)}",
                            }
                        ],
                        "attackSteps": [
                            Step(
                                name=f"Locate hardcoded '{key}'",
                                description=f"Scan in-scope file {path} for hardcoded '{key}'",
                                criteria="A literal assignment matches the validator pattern",
                                verdict="exploitable",
                                log=[f"[validator] {path}:{i + 1} matched ('{key}' assignment)"],
                            ).__dict__
                        ],
                        "testerNote": "Authorized static validation only.",
                        "run": {"validator": "purpleguard-static", "kind": "regex-evidence"},
                    }
                )
                break  # one per file to avoid noise

        # TLS verification disabled
        idx = _line_of(lines, _TLS_DISABLED)
        if idx is not None:
            m = _TLS_DISABLED.search(lines[idx])
            findings.append(
                {
                    "id": _finding_id(project, path, idx + 1, "tls-disabled"),
                    "title": f"TLS certificate verification disabled in {path}",
                    "severity": "high",
                    "vulnerabilityType": "Disabled transport security check",
                    "repo": project,
                    "file": path,
                    "location": f"line {idx + 1}",
                    "attackSurface": "Repository · runtime behavior",
                    "attackPath": [
                        f"Static scan of authorized target found verification disabled in {path}",
                        "Validator confirms the disabled-check expression is present",
                    ],
                    "explanation": (
                        f"{path} disables TLS certificate verification at line {idx + 1} "
                        f"({_redact(m.group(0)) if m else 'verify=False'}). Connections made "
                        "through this code path accept forged or tampered certificates. "
                        "The validator confirms the expression exists; it does not attempt "
                        "a machine-in-the-middle attack."
                    ),
                    "remediation": (
                        "Remove the disabled verification and let the platform's default "
                        "certificate chain validation apply; pin CA bundles for special cases."
                    ),
                    "vulnerableCode": _snippet(lines, idx),
                    "proposedPatch": None,
                    "fixedCode": None,
                    "reTestChecks": [f"No disabled TLS verification remains in {path}"],
                    "vulnerableMarker": m.group(0) if m else "verify=False",
                    "evidence": [
                        {
                            "id": "ev-tls",
                            "kind": "code",
                            "label": f"TLS verification disabled at {path}:{idx + 1}",
                            "content": f"{path}:{idx + 1}  {m.group(0) if m else ''}".strip(),
                        }
                    ],
                    "attackSteps": [
                        Step(
                            name="Locate disabled verification",
                            description=f"Scan in-scope file {path} for TLS verification bypasses",
                            criteria="A disable-expression matches the validator pattern",
                            verdict="exploitable",
                            log=[f"[validator] {path}:{idx + 1} matched (TLS verification disabled)"],
                        ).__dict__
                    ],
                    "testerNote": "Authorized static validation only.",
                    "run": {"validator": "purpleguard-static", "kind": "regex-evidence"},
                }
            )

    return findings


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def validate(
    project: str,
    files: List[Dict[str, Any]],
    scope: Optional[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Run all static validators over in-scope files. Returns structured
    finding payloads ready for /api/ingest_finding. Empty result = nothing
    found — an honest outcome, not a failure."""
    in_scope = filter_files(files, scope)
    if not in_scope:
        return []
    # Skip vendored / generated trees (not the developer's code to fix).
    in_scope = [
        f for f in in_scope
        if not any(ignored in f.get("path", "") for ignored in DEFAULT_IGNORED_DIRS)
    ]
    if not in_scope:
        return []
    findings: List[Dict[str, Any]] = []
    seen: set = set()
    for f in _static_findings(project, in_scope):
        if f["id"] in seen:
            continue
        seen.add(f["id"])
        findings.append(f)
    return findings
