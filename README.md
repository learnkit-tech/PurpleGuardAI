# PurpleGuardAI

Autonomous security scanner for Python codebases with adversarial
validation and conservative, provable remediation.

PurpleGuardAI does not stop at pattern matching. It pairs a static
scanner with a **Hacker** engine that discovers attack paths, plans
controlled attacks against an authorized local target, validates them
at runtime, and only then proposes a fix - which is verified three
independent ways before the project is declared secure.

```
Hacker discovers vulnerability
        ↓
Attack path / finding
        ↓
Planner decides what to validate
        ↓
Validator confirms the vulnerability (controlled payload)
        ↓
Patcher proposes a conservative fix
        ↓
Developer approval (nothing is modified before --approve)
        ↓
Remediation
        ↓
Re-test: static rescan + automated tests + adversarial re-attack
        ↓
Final security verdict
```

## Rules

| Rule  | Vulnerability      | Severity | Auto-fix |
|-------|--------------------|----------|----------|
| PG001 | Hardcoded Password | HIGH     | Yes      |
| PG002 | Dangerous eval     | HIGH     | Yes      |
| PG003 | Hardcoded Secret   | HIGH     | Yes      |
| PG004 | SQL Injection      | HIGH     | Yes      |
| PG005 | Command Injection  | CRITICAL | Yes      |
| PG006 | Path Traversal     | HIGH     | Yes (provable shapes only) |
| PG007 | Cross-Site Scripting | HIGH   | Yes      |
| PG008 | Open Redirect      | HIGH     | Yes      |
| PG009 | SSRF               | HIGH     | No - manual review |

## Auto-fix policy

Remediation is deliberately conservative. A finding is only
auto-fixable when a **provably safe** transformation exists for its
exact code shape; per-finding provability is decided by dry-running
the fix in memory (`CodePatcher.can_auto_fix`). Anything that cannot
be proven stays a finding requiring review rather than silently
modifying code.

Examples of supported transformations:

- `eval(expr)` -> `ast.literal_eval(expr)`
- `os.system(cmd)` -> `subprocess.run(shlex.split(cmd), shell=False)`
- `Response(...)` / `make_response(...)` -> wrapped in
  `markupsafe.escape(...)`
- redirects guarded to relative-only destinations
- `target = base / filename` -> resolved and confined with
  `is_relative_to(base)` plus an explicit `raise`

SSRF (PG009) is intentionally never auto-fixed: destination
allowlists are application-specific, so the finding is surfaced for
manual review with a recommendation instead.

## The Hacker engine

The Hacker performs **authorized local** adversarial validation.
It starts the target application, sends controlled payloads, and
checks behavioral evidence:

- Payloads are harmless markers (`2+3`, `true; echo MARKER`,
  TEST-NET addresses such as `192.0.2.x`).
- Redirects are never followed; evidence comes from the server's own
  `Location` header.
- SSRF confirmation relies on the target's own error text proving it
  attempted the attacker-chosen destination. No external network
  access is performed.

Every confirmed attack becomes a `ConfirmedFinding` that the
remediation adapter converts into a PurpleGuard finding with source,
sink, payload, and evidence attached.

## CLI

```bash
# Scan and generate reports (JSON + HTML by default)
python main.py scan <target> [--json] [--html] [--severity HIGH]

# Review queue: auto-fixable vs. manual review
python main.py review <target>

# Remediate (two-step approval; no files are touched without --approve)
python main.py secure <target> [--approve]

# Restore a file from its PurpleGuard backup
python main.py rollback <file>
```

The review queue is the day-to-day workflow: it lists what the tool
can fix safely (with the exact approval command) and what needs a
human, including the recommendation for each manual-review finding.

## Adversarial E2E

```bash
python scripts/hack.py tests/hacker_target_web
```

Runs the full Hacker pipeline (recon -> plan -> attack -> report)
against the deliberately vulnerable fixture and writes
`reports/hacker_report.json`.

## Verification after remediation

Patched code is never trusted blindly. After applying approved
fixes, PurpleGuard:

1. **Re-scans statically** - the remediated file must pass its own
   rule (guards are whitelisted by the scanner).
2. **Runs the project's tests**.
3. **Re-attacks** - replays every confirmed Hacker finding against
   the remediated target; the payload must now be blocked.
4. Produces a final verdict only if all three layers agree.

## Installation

Requires Python >= 3.10.

```bash
pip install purpleguard-ai

# or from source
pip install .
purpleguard --help
```

Development:

```bash
pip install -e .[dev]
pytest tests/ -q
python scripts/check_packaging.py   # packaging sanity check
```

## Project layout

```
main.py                     CLI entry point (scan/secure/rollback/review)
purpleguard_cli.py          console-script wrapper for the installed CLI
scanner/
  rules/                    static detection rules (PG001-PG009)
  knowledge/                rule metadata and recommendations
  remediation/              patcher, workflow, diffs
  verification/             static rescan, tests, final verdict
  developer/                developer session (secure_all workflow)
hacker/
  python_analyzer.py        taint tracking, source/sink discovery
  planner.py                attack-path -> validator planning
  validation/               local target runner + payload validators
  findings.py               ConfirmedFinding model
  remediation_adapter.py    hacker findings -> PurpleGuard findings
  reverification.py         adversarial re-attack after remediation
tests/
  unit/                     unit and integration tests
  hacker_target/            deliberately vulnerable fixture (CLI)
  hacker_target_web/        deliberately vulnerable fixture (web)
```

## CI

GitHub Actions (`.github/workflows/ci.yml`) runs the test suite on
Python 3.10 and 3.12, the packaging sanity check, and a full
wheel-build smoke test that installs the built distribution and
invokes the `purpleguard` console script.

## Authorization

PurpleGuardAI is a defensive tool. Its adversarial features are
restricted to local, authorized targets (applications you own). The
Hacker only sends harmless, controlled payloads and never performs
destructive actions or external network access.

## License

MIT
