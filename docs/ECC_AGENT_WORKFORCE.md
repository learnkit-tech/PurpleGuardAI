# ECC → PurpleGuard Security Agent Workforce

**Provenance:** curated snapshot from ECC commit `9c19aabe0f6506a4d0f47945e3f6cae59d7e4e7c`
(`learnkit-tech/ECC`, upstream `affaan-m/ECC`). See `docs/ECC_EXTRACTION_MANIFEST.md`,
`docs/ECC_CAPABILITY_MAP.md`, and `ecc/MANIFEST.json`. This is a curated ECC snapshot extracted into
PurpleGuardAI; the upstream ECC repository remains separate and untouched.

**Central idea:** ECC's specialized agents (roles, instructions, knowledge, skills, rules, and
orchestration patterns) are a primary product asset. PurpleGuard does not merely "use ECC"; it turns
those agents into a coordinated **Security Agent Workforce** that performs continuous security
assessment, while PurpleGuard keeps authoritative security state, authorization, and the approval
gate.

The workforce is a **PurpleGuard-native subsystem** at [`security_workforce/`](../security_workforce/README.md).
The vendored `ecc/` snapshot is the source of knowledge and provenance, not a runtime dependency.

---

## 1. Method

- The extracted snapshot is `ecc/agents/`, `ecc/commands/`, `ecc/rules/`, `ecc/skills/`,
  `ecc/schemas/`, `ecc/ecc2/`, `ecc/agent.yaml`, `ecc/ecc2.toml`.
- Every claim below is read from the actual agent frontmatter (`name`, `description`, `tools`,
  `model`) — no capability is invented. An agent whose adapter is not implemented is
  `defined_only`, never `available`.

## 2. Totals (from the audited source)

| Metric | Value |
|---|---|
| Total ECC agents in the source repository | **67** |
| Agents audited and classified | **67** |
| Agents selected into the curated snapshot | **20** |
| Agents adapted into the registry with provenance | **20** |
| Agents with a real implemented adapter (executable) | **13** |
| Agent role categories defined | **8** |
| Agent roles with no engine path (`unavailable`, reason documented) | **7** |
| Agents granted `modify` | **0** (by construction) |
| Agents intentionally excluded (non-security) | **2** (`seo-specialist`, `marketing-agent`) |

## 3. Role categories and the workforce model

```
COMPANY → PURPLEGUARD → SECURITY AGENT WORKFORCE
        → CONTINUOUS ASSESSMENT → FINDINGS/EVIDENCE/RISK → VALIDATION
        → DEVELOPER HANDOFF → APPROVAL → REMEDIATION → RE-TEST → VERIFICATION
        → CONTINUOUS MONITORING ↺
```

The workforce is **coordinated**, not 60 independent scanners:

```
WorkforceOrchestrator  (security_workforce/orchestrator.py — implemented)
  ├─ selects the specialized agent for an operation (routing)
  ├─ checks the agent's permission grant (least privilege)
  ├─ runs the agent's real adapter against a real target (real execution)
  ├─ normalizes the AgentResult (no raw agent output becomes security truth)
  ├─ evaluates quality (authoritative / requires_validation)
  ├─ correlates into canonical findings (dedupe + evidence + corroboration)
  └─ persists and exposes it by task_id / correlation_id
```

Defined role categories: `reconnaissance`, `vulnerability_analysis`, `attack_path_analysis`
(reserved), `validation`, `monitoring` (reserved), `remediation` (reserved), `verification`,
`orchestration`.

## 4. Agent-by-agent mapping — the 20 extracted agents

`Aut.` = autonomy (`auto` = may run without approval; `appr` = requires approval for its propose
step). All are read-only today; none may modify source.

| ECC agent | PG category | Responsibility (from ECC) | Permissions | Aut. | Adapter |
|---|---|---|---|---|---|
| `security-reviewer` | vulnerability_analysis | OWASP/Top-10 vuln + secrets + injection detection | observe, analyze | auto | **available** |
| `database-reviewer` | vulnerability_analysis | PostgreSQL/Supabase schema + query review | observe, analyze | auto | **available** (injection rules) |
| `mle-reviewer` | vulnerability_analysis | ML pipeline/eval/serving/rollback review | observe, analyze | auto | **available** (deserialization rules) |
| `network-config-reviewer` | vulnerability_analysis | Network config review | observe, analyze | auto | unavailable |
| `code-explorer` | reconnaissance | Repository/code structure exploration | observe, analyze | auto | **available** (ProjectAnalyzer) |
| `comment-analyzer` | reconnaissance | Comment/docstring analysis | observe, analyze | auto | **available** (PG012) |
| `spec-miner` | reconnaissance | Extract behavioral specs from a codebase | observe, analyze | auto | unavailable |
| `network-architect` | reconnaissance | Infrastructure/network context analysis | observe, analyze | auto | unavailable |
| `code-reviewer` | validation | Quality + security review of changes | observe, analyze | auto | **available** (hacker analyzer) |
| `python-reviewer` | validation | Python-specific review (PEP8, types, security) | observe, analyze | auto | **available** (scanner) |
| `network-troubleshooter` | validation | Diagnose network faults | observe, analyze | auto | unavailable |
| `silent-failure-hunter` | validation | Find silently swallowed errors/failures | observe, analyze | auto | **available** (PG011) |
| `e2e-runner` | validation | End-to-end flow verification and artifacts | observe, analyze, validate | appr | **available** (dynamic engine) |
| `agent-evaluator` | verification | 5-axis evaluation of agent output | observe, analyze, verify | auto | **available** |
| `tdd-guide` | verification | Tests-first methodology; regression enforcement | observe, analyze, verify, propose | appr | **available** (verification engine) |
| `architect` | orchestration | System design and trade-offs | observe, analyze, propose | auto | unavailable |
| `planner` | orchestration | Implementation/assessment planning | observe, analyze, propose | auto | **available** |
| `chief-of-staff` | orchestration | Coordination and task delegation | observe, analyze, propose | auto | **available** |
| `loop-operator` | orchestration | Run/monitor autonomous loops safely | observe, analyze | auto | unavailable (no real scheduler) |
| `harness-optimizer` | orchestration | Harness reliability/cost/throughput tuning | observe, analyze, propose | appr | unavailable |

**Explicit correction:** `security-reviewer.md` declares tools including `Write`/`Edit`/`Bash`, but
PurpleGuard grants this agent only **observe + analyze** in this implementation. Declared tools are
not permissions.

## 5. Full ECC catalog — the remaining 47 agents

Security/quality-adjacent, **adapt later** (not extracted yet; available upstream):
`code-architect`, `code-simplifier`, `conversation-analyzer`, `performance-optimizer`,
`pr-test-analyzer`, `type-design-analyzer`, `refactor-cleaner`, `doc-updater`, `docs-lookup`,
`a11y-architect`, `homelab-architect`, `healthcare-reviewer`,
`django-reviewer`, `fastapi-reviewer`, `go-reviewer`, `java-reviewer`, `kotlin-reviewer`,
`csharp-reviewer`, `cpp-reviewer`, `rust-reviewer`, `swift-reviewer`, `php-reviewer`,
`react-reviewer`, `vue-reviewer`, `typescript-reviewer`, `flutter-reviewer`, `fsharp-reviewer`.

**Infrastructure / build-only** (keep upstream; not a PurpleGuard security role):
`build-error-resolver` and its per-language variants (`cpp-`, `dart-`, `django-`, `go-`, `java-`,
`kotlin-`, `pytorch-`, `react-`, `rust-`, `swift-` `build-resolver`), `harmonyos-app-resolver`,
`gan-evaluator`, `gan-generator`, `gan-planner`, `opensource-forker`, `opensource-packager`,
`opensource-sanitizer`.

**Intentionally excluded** (not cybersecurity): `seo-specialist`, `marketing-agent`.

(20 extracted + 47 not extracted = 67.)

## 6. Permission model

Six explicit permissions, separated so analysis never implies modification:

| Permission | Meaning |
|---|---|
| `observe` | read target/repository context |
| `analyze` | derive findings/evidence |
| `validate` | exercise the target to confirm behavior (authorized, read-only) |
| `propose` | produce recommendations/patches (no apply) |
| `modify` | change source — **never granted to an agent** |
| `verify` | re-check a remediation and its evidence |

The orchestrator rejects a task whose required permissions exceed the agent's grant (`REJECTED`).
`MODIFY` stays behind PurpleGuard's existing approval gate (`purpleguard_runner.py --approve`). No
agent bypasses authorization, approval, developer review, or the existing remediation controls.

## 7. Context / memory model

Agents must not start from zero, and must not receive unlimited context. `security_workforce/context.py`
builds five scopes: **global** (policy/workforce), **project** (project id, target), **task**,
**agent** (per-agent), **historical** (prior result count, prior task ids, canonical-finding count).
A bounded history limit keeps context from growing without bound. PurpleGuard remains the
authoritative security state owner; the workforce consumes and contributes structured context only.

## 8. Orchestrator design

`security_workforce/orchestrator.py` (implemented now, small and real):

1. **discover** agents (`load_registry` / `validate_registry`),
2. **route** operation → agent (`_ROUTING`),
3. **authorize** (required permissions ⊆ granted, else `REJECTED`),
4. **execute** the agent's adapter against a real target,
5. **evaluate** quality (`authoritative`, `requires_validation`),
6. **correlate** into canonical findings (dedupe, evidence merge, corroboration),
7. **normalize + persist** the `AgentResult` and expose it by `task_id`.

Target end-state responsibilities (documented, not implemented): read current security state →
decide required assessment → select agents → provide context → execute/schedule → collect →
correlate → request validation → update security state → trigger developer workflow → monitor
remediation → trigger verification → return to monitoring. It must **not** run every agent on every
cycle; specialization and routing are mandatory.

## 8b. Evaluation, correlation, and persistence

- **Evaluation** (`evaluation.py`): 7 axes (accuracy, completeness, evidence-quality,
  reproducibility, clarity, actionability, confidence) → `authoritative` + `requires_validation`.
  Documented thresholds: high/critical findings always require validation; results below an
  evidence-quality floor are non-authoritative.
- **Correlation** (`correlation.py`): stable fingerprint (rule + file + line + code) groups
  findings across agents into canonical findings; merges evidence; preserves `sources`
  (agent/task/correlation); marks `corroborated` only when ≥2 distinct agents agree. Five agents
  reporting one weakness yield one canonical finding.
- **Persistence** (`store.py`): `reports/security_workforce.json` (gitignored runtime state),
  retrievable by `task_id`.

## 9. Continuous assessment architecture

Real requirements (documented; **not faked**):

- **Trigger sources:** schedule, repository change, dependency change, deployment change,
  configuration change, new attack surface, regression check on previously vulnerable areas,
  periodic review.
- **Real state required:** task state, execution state, evidence, results — no timers that merely
  claim agents are working.
- **Status:** the execution primitive (`WorkforceOrchestrator.run`) is real and synchronous. The
  **scheduler/trigger layer is NOT implemented yet** — it is the next implementation stage. No fake
  monitoring exists (enforced by a test that forbids `time.sleep`/`threading.Timer` in the package).

## 10. Bridge design

`ecc/bridge/` is the only surface PurpleGuard page-level code imports from the snapshot. It exposes
real **runtime capabilities** (`EccBridge`: `ecc.snapshot.catalog`, `ecc.harness.describe`,
`agent.evaluate`, `integration.aura.trust_check`; `ecc2.*` returns honest `ECC_UNAVAILABLE`). The
**agent workforce** is no longer part of `ecc/bridge/` — it is PurpleGuard-native under
`security_workforce/`, which imports **no** ECC internals. Both speak the same contract primitives
(deterministic `task_id`/`correlation_id`, structured results/errors).

## 11. First vertical slice — implemented (real)

`security.review` → `security-reviewer`:

1. **one real agent capability** — `SecurityReviewerAgent` (role from
   `ecc/agents/security-reviewer.md`),
2. **one real task** — `WorkforceOrchestrator.run("security.review", target=...)`,
3. **real execution** — runs PurpleGuard's `scanner.engine.SecurityScanner` over the target,
4. **real structured result** — `AgentResult` (`agent_id`, `task_id`, `correlation_id`, `role`,
   `status`, `findings`, `evidence`, `recommendations`, `confidence`, `errors`, `metadata`),
5. **PurpleGuard persistence** — `WorkforceStore` → `reports/security_workforce.json`,
6. **evidence** — normalized per-finding evidence (rule id, severity, relative file, line, code),
7. **correlation IDs** — deterministic `task_id`/`correlation_id` from an idempotency key,
8. **agent/task status** — `completed | failed | rejected | unavailable`,
9. **no fake results** — read-only; no source mutation; unavailable is explicit.

Verified example (real run): a target containing `eval(x)` and `os.system('ping '+x)` produced
`PG002` and `PG005` (CRITICAL) with evidence, persisted by `task_id`, with the same id on a repeat
submission with the same idempotency key; the evaluation marked it `requires_validation` and
non-authoritative.

### 11.1 Expanded vertical slices (real execution)

Beyond `security-reviewer`, 12 more capabilities now execute a real engine:

- **Rule-filtered scanner agents** — `database-reviewer` (PG004/PG005), `mle-reviewer`
  (PG010/PG002), `python-reviewer` (all rules, `.py` sources).
- **New engine rules** — `silent-failure-hunter` (PG011, swallowed exceptions) and
  `comment-analyzer` (PG012, secret in comment). These are real scanner rules added under
  `scanner/rules/` and exposed as an *optional* rule set, so the default scan is unchanged.
- **Reconnaissance** — `code-explorer` runs `ProjectAnalyzer` (languages/framework/deps/attack
  surface) and produces observations, not vulnerability findings.
- **Independent validation** — `code-reviewer` runs PurpleGuard's Hacker analyzer
  (`hacker.python_analyzer`), a second, independently implemented engine.
- **Dynamic validation** — `e2e-runner` runs the Hacker orchestrator's discover/plan/validate
  against a PurpleGuard-owned local target (approval-gated).
- **Verification** — `agent-evaluator` (native quality gate), `tdd-guide` (the verification
  engine's test layer).
- **Orchestration** — `planner` and `chief-of-staff` operate over real registry/store state.

### 11.2 Multi-agent validation (Phase 3)

`WorkforceOrchestrator.assess(target)` runs discovery (`security-reviewer`, scanner) and
independent validation (`code-reviewer`, hacker analyzer), then correlates. A canonical finding is
marked `corroborated` only when ≥2 distinct agents produced evidence for it; a single agent is
reported honestly as `unvalidated`. `assessment["corroboration"]` records the participating agents,
the distinct engines, and whether independent corroboration actually occurred.

### 11.3 Hacker → Developer loop (Phase 4)

`DeveloperHandoff` sends canonical findings to the developer inbox (`awaiting_approval`, mirrored
into `dev_agent/status.json`), enforces the approval gate, applies approved remediation through the
existing `RemediationWorkflow`, then re-tests with `SecurityScanner`. `verified` is only set when the
rule no longer fires; a fix with no automated transformer stays `REMEDIATION_UNAVAILABLE`. The
workforce is exposed read-only through `/workforce/capabilities`, `/workforce/findings`,
`/workforce/assess`, and `/workforce/handoff`.

## 12. Tests

- `tests/unit/test_security_workforce.py` — registry, playbooks, capability mapping, routing, task
  lifecycle, deterministic IDs, structured result, evidence, evaluation, correlation/dedupe, agent
  failure, unavailable agent, malformed result normalization, authorization boundary, no source
  mutation, context scopes/history, provenance, boundary (no ECC import), no-fake-monitoring.
- `tests/unit/test_security_workforce_adapters.py` — per-adapter real execution, the new engine
  rules (PG011/PG012), engine-unavailable, engine-failure, permission rejection, evidence,
  provenance, persistence.
- `tests/unit/test_security_workforce_e2e.py` — deterministic authorized E2E (target → engine →
  multi-agent validation → canonical finding → developer → approval → remediation → re-test →
  VERIFIED), the negative path (engine unavailable → no fabricated finding), and live dynamic
  validation against the controlled fixture.
- `tests/unit/test_ecc_extraction.py` — snapshot integrity/provenance.

## 13. Operationalization status

1. **Done** — 13 adapters execute real PurpleGuard engines over authorized targets.
2. **Done** — multi-agent discovery + independent validation
   (`security-reviewer` scanner + `code-reviewer` hacker analyzer) with honest corroboration.
3. **Done** — canonical finding → developer handoff → approval → remediation → re-test →
   verification (`security_workforce/developer_handoff.py`).
4. **Done** — workforce state exposed through the existing API (`/workforce/*`).
5. **Not implemented (honest)** — the continuous-assessment **scheduler**. It is deliberately
   absent rather than faked with timers; `loop-operator` is reported `UNAVAILABLE`.
6. **Unavailable capabilities** — architect, spec-miner, network-architect, network-config-reviewer,
   network-troubleshooter, loop-operator, harness-optimizer (each with a documented missing engine).

## Blockers

- ECC upstream push remains denied (403) — unrelated to PurpleGuard; the snapshot is self-contained.
- Agent-Reach is unavailable and not fabricated.
- `ecc2` (Rust) cannot be built here (no cargo/rustc) — `ecc2.*` is honestly `ECC_UNAVAILABLE`.
- Continuous assessment (scheduler) is **not implemented** and not faked; the validation path IS implemented.
