# PurpleGuard Security Agent Workforce

A **PurpleGuard-native** subsystem: a coordinated team of specialized security
agents that performs authorized security assessment and feeds PurpleGuard's
authoritative security state.

> ECC is the **source**. PurpleGuard is the **product**. The workforce is the **capability**.
> The vendored ECC snapshot lives in `ecc/` for provenance. See
> [`docs/ECC_CAPABILITY_MAP.md`](../docs/ECC_CAPABILITY_MAP.md) and
> [`docs/ECC_AGENT_WORKFORCE.md`](../docs/ECC_AGENT_WORKFORCE.md).

```python
from security_workforce import WorkforceOrchestrator, DeveloperHandoff

workforce = WorkforceOrchestrator()

# single focused review (real engine execution)
outcome = workforce.run("security.review", target="/path/to/project")

# genuine multi-agent discovery + independent validation
assessment = workforce.assess("/path/to/project")
assessment["canonical_findings"]     # deduplicated, evidenced, provenance-preserving
assessment["corroboration"]          # did independent corroboration actually occur?

# Hacker -> Developer handoff (approval is a real gate)
handoff = DeveloperHandoff(workforce.store)
handoff.send(assessment["canonical_findings"], target="/path/to/project")
handoff.approve_and_remediate(fingerprint, approve=True)  # remediation -> re-test -> VERIFIED
```

## Scripts

```
AUTHORIZED PROJECT → REAL SECURITY ENGINE → MULTI-AGENT VALIDATION
→ CORRELATION/DEDUPLICATION → CANONICAL FINDING → PERSISTENCE
→ HACKER SURFACE → DEVELOPER WORKSPACE → EXPLICIT APPROVAL
→ REMEDIATION → RE-TEST → VERIFICATION
```

## Capabilities: what actually executes

13 of the 20 adapted capabilities are backed by a real engine adapter and are
**executable**. The remaining 7 have no engine primitive and are reported
`UNAVAILABLE` with the exact missing dependency — never faked.

| Capability | Operation | Engine | State |
|---|---|---|---|
| security-reviewer | `security.review` | `scanner.engine.SecurityScanner` | AVAILABLE |
| database-reviewer | `security.review.database` | SecurityScanner (injection rules) | AVAILABLE |
| mle-reviewer | `security.review.ml` | SecurityScanner (deserialization/code-exec) | AVAILABLE |
| python-reviewer | `security.review.python` | SecurityScanner (python files) | AVAILABLE |
| code-reviewer | `security.review.diff` | `hacker.python_analyzer` (independent engine) | AVAILABLE |
| code-explorer | `security.recon` | `scanner.analyzer.ProjectAnalyzer` | AVAILABLE |
| silent-failure-hunter | `security.review.error-paths` | `SilentFailureRule` (PG011) | AVAILABLE |
| comment-analyzer | `security.review.comments` | `CommentSecretRule` (PG012) | AVAILABLE |
| e2e-runner | `security.validate.e2e` | `hacker.orchestrator` (approval-gated) | AVAILABLE |
| agent-evaluator | `security.verify.result-quality` | native quality gate | AVAILABLE |
| tdd-guide | `security.verify.regression` | `scanner.verification.engine` | AVAILABLE |
| planner | `security.plan` | workforce orchestrator | AVAILABLE |
| chief-of-staff | `security.coordinate` | workforce orchestrator | AVAILABLE |
| architect | `security.assess.design` | — | UNAVAILABLE (no design/threat-model engine) |
| spec-miner | `security.recon.invariants` | — | UNAVAILABLE (no invariant-extraction engine) |
| network-architect | `security.recon.network` | — | UNAVAILABLE (no topology engine) |
| network-config-reviewer | `security.review.config` | — | UNAVAILABLE (no config-parsing engine) |
| network-troubleshooter | `security.validate.network` | — | UNAVAILABLE (no network diagnostic engine) |
| loop-operator | `security.monitor` | — | UNAVAILABLE (no real scheduler; timers forbidden) |
| harness-optimizer | `security.optimize` | — | UNAVAILABLE (no metrics engine) |

`workforce.capabilities()` returns this table with live `AVAILABLE` / `UNAVAILABLE`
states. Two new rules were added to the scanner engine: `PG011` (swallowed
exception) and `PG012` (secret in comment). They are **optional** engine rules
(`scanner/rules/optional.py`), so the default scan output for existing callers is
unchanged.

## Multi-agent validation

`workforce.assess(target)` runs a discovery agent and an independent-validation
agent that use **different engine implementations**:

```
security-reviewer  → scanner.engine.SecurityScanner        (discovery)
code-reviewer      → hacker.python_analyzer                (independent validation)
        ↓
correlation / deduplication (fingerprint = rule + location)
        ↓
canonical finding (corroborated only when ≥2 distinct agents produced evidence)
```

A finding is marked `corroborated` **only** when two or more distinct agents
independently reported it. A single agent is represented honestly as
`unvalidated` — corroboration is never manufactured.

## Developer workflow (Phase 4)

`DeveloperHandoff` connects canonical findings to the existing developer loop:

* `send()` → developer inbox (`awaiting_approval`) + `dev_agent/status.json` security block.
* `approve_and_remediate(approve=False)` → `APPROVAL_REQUIRED`; **no source modified**.
* `approve_and_remediate(approve=True)` → existing `RemediationWorkflow` applies the
  approved patch, then a **genuine re-test** (`SecurityScanner`) decides the verdict.
* `verified` is set only when the rule no longer fires. A fix with no automated
  transformer stays `REMEDIATION_UNAVAILABLE` — never auto-verified.

This reuses PurpleGuard's existing remediation, scanner, and status subsystems; it
is not a parallel backend.

## Layout

```
security_workforce/
├── contracts.py            # tasks, results, evidence, permissions, states, deterministic IDs
├── capabilities.py         # agent → operation → engine mapping + honesty flags
├── registry/agents.json    # 20 agent contracts (role, permissions, engine, provenance)
├── playbooks/registry.json # 5 security playbooks
├── agents/engine_agent.py  # generic engine-backed agent (truthful state normalization)
├── adapters/               # real engine seams (scanner, project, hacker-static, dynamic, …)
├── evaluation.py           # quality gate (authoritative / requires_validation)
├── correlation.py          # canonical findings (dedupe + evidence + corroboration)
├── context.py              # scoped context/memory
├── store.py                # persistence: reports/security_workforce.json (gitignored)
├── developer_handoff.py    # canonical finding → developer → approval → remediation → re-test
└── orchestrator.py         # route → authorize → execute → evaluate → correlate → persist
```

## Permissions (least privilege)

`observe → analyze → validate → propose → modify → verify`. **No agent holds `modify`.**
Source changes stay behind the human approval gate. Agents that perform active
testing (`e2e-runner`) require an explicit `approved=True` flag.

## Continuous assessment

The execution primitive is real and synchronous. A continuous-assessment
scheduler is **not implemented** and is not faked — there is no `time.sleep` or
`threading.Timer` anywhere in this package (a test enforces this). `loop-operator`
is therefore reported `UNAVAILABLE`.

## Provenance

Agent knowledge is adapted from the curated ECC snapshot pinned at
`ECC_SOURCE_COMMIT = 9c19aabe0f6506a4d0f47945e3f6cae59d7e4e7c` (`learnkit-tech/ECC`).
Every registry entry records `provenance.ecc_source` / `provenance.ecc_commit`.
`Agent-Reach` is absent from the audited source and is **not** fabricated.

## Tests

* `tests/unit/test_security_workforce.py` — registry, playbooks, routing, IDs,
  contracts, evidence, evaluation, correlation, normalization, permissions, boundary.
* `tests/unit/test_security_workforce_adapters.py` — per-adapter execution, the
  new engine rules, engine-unavailable, engine-failure, permission rejection,
  evidence, provenance, persistence.
* `tests/unit/test_security_workforce_e2e.py` — deterministic authorized E2E
  (target → engine → multi-agent → canonical → developer → approval → remediation
  → re-test → VERIFIED), the negative path (engine unavailable → no fabricated
  finding), and live dynamic validation against the controlled fixture.
