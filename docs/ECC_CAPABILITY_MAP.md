# ECC → PurpleGuard Capability Map

**Provenance:** curated snapshot from ECC commit `9c19aabe0f6506a4d0f47945e3f6cae59d7e4e7c`
(`learnkit-tech/ECC`, upstream `affaan-m/ECC`, MIT). See `docs/ECC_EXTRACTION_MANIFEST.md`,
`ecc/MANIFEST.json`, `ecc/PROVENANCE.md`. This is a curated ECC snapshot extracted into
PurpleGuardAI; the upstream ECC repository remains separate and untouched.

This document is the **capability analysis**: for each reusable ECC capability, what it is, why it
matters to PurpleGuard, where it lives now, and whether it was copied, adapted, referenced,
reimplemented, deferred, or excluded.

Legend: **COPY** (vendored verbatim under `ecc/`) · **ADAPT** (knowledge reimplemented natively
under `security_workforce/`) · **REFERENCE** (kept in `ecc/` for provenance, not executed) ·
**REIMPL** (concept reimplemented natively) · **DEFER** · **EXCLUDE**.

---

## A–T capability analysis

| # | Capability | ECC source | Original purpose | PurpleGuard adaptation | Where | Mode |
|---|---|---|---|---|---|---|
| A | Specialized agent knowledge | `ecc/agents/*.md` (67; 20 extracted) | Curated role prompts/instructions | Role, mission, domains, skills adapted into agent contracts | `security_workforce/registry/agents.json` | ADAPT |
| B | Agent roles | `ecc/agents/` frontmatter | Role identity per agent | 8 security role categories mapped to 20 agents | registry + `docs/ECC_AGENT_WORKFORCE.md` | ADAPT |
| C | Security-relevant skills | `ecc/skills/` (16 extracted) | Reusable procedures (review, eval, research) | Playbook steps + evaluation method | `security_workforce/playbooks/`, `evaluation.py` | ADAPT |
| D | Rules / operating constraints | `ecc/rules/{common,python,web}` | Coding/review constraints | Agent `rules` fields; read-only default; no-`modify` policy | registry, contracts | ADAPT |
| E | Security workflows | `ecc/commands/` (41 extracted) | Slash-command workflows | Security playbooks (trigger → steps → evidence → gate) | `security_workforce/playbooks/registry.json` | ADAPT |
| F | Orchestration patterns | `ecc/agents/{planner,architect,chief-of-staff}.md`, `ecc/ecc2` | Planning/delegation/control plane | `WorkforceOrchestrator` route→authorize→execute→evaluate→correlate→persist | `security_workforce/orchestrator.py` | REIMPL |
| G | Task decomposition | `ecc/commands`, `agents/planner.md` | Break work into steps | Playbook steps + task contract | playbooks, `contracts.py` | ADAPT |
| H | Multi-agent coordination | `ecc/agents/chief-of-staff.md`, skills | Delegate across agents | Routing + correlation/corroboration across agents | orchestrator, `correlation.py` | REIMPL |
| I | Research-first workflows | `ecc/skills/search-first`, `agents/code-explorer.md` | Investigate before acting | Reconnaissance category agents (defined_only) | registry | ADAPT |
| J | Memory / context management | `ecc/skills/context-*`, `agents/comment-analyzer.md` | Context preservation | Scoped context model (global/project/task/agent/historical) | `context.py` | ADAPT |
| K | Session / state management | `ecc/ecc2/src/session`, `worktree` | Durable session/worktree isolation | Concept retained; task/result persistence native | `store.py`; ecc2 REFERENCE | ADAPT |
| L | Verification / quality gates | `ecc/agents/{e2e-runner,tdd-guide}.md` | Gate work on checks | Evaluation quality gate + `requires_validation` | `evaluation.py` | ADAPT |
| M | Agent evaluation | `ecc/skills/agent-self-evaluation`, `agents/agent-evaluator.md` | Multi-axis output scoring | 7-axis scorer + authoritative decision | `evaluation.py` | REIMPL |
| N | Event / hook patterns | `ecc/ecc2/src/comms`, `observability` | Eventing/observability | Event-model design documented (not implemented) | `docs/SECURITY_AGENT_WORKFORCE.md` | DEFER |
| O | Security tooling patterns | `ecc/agents/security-reviewer.md`, skills | Security review methodology | Static review adapter over `scanner.engine` | `adapters/scanner.py` | ADAPT |
| P | Parallel agent execution | `ecc/ecc2` (tokio), `agents/chief-of-staff.md` | Concurrent work | Sequential/synchronous today; parallelism deferred | — | DEFER |
| Q | Cost / context optimization | `ecc/agents/harness-optimizer.md`, `skills/context-*` | Reduce token/tool cost | Bounded context (history limit); deferred further | `context.py` | ADAPT/DEFER |
| R | Learning / improvement | `ecc/skills/`, `research/` | Iterate on process | Canonical-finding history enables regression learning later | `correlation.py` | DEFER |
| S | Error / failure handling | `ecc/ecc2` error paths | Robust failure handling | Structured error codes; fail-closed normalization | `contracts.py`, `orchestrator.py` | REIMPL |
| T | Auditability / observability | `ecc/ecc2/src/observability` | Trace/observe execution | Structured results, task/correlation IDs, provenance, evidence | contracts, store | ADAPT |

**Post-capability categories with no audited source inside `ecc/`** (not fabricated):
`attack_path_analysis` agents beyond `security-reviewer`'s static analysis, `monitoring` agents, and
dedicated `remediation` agents — reserved role categories, no adapter yet.

---

## Disposition ledger (KEEP / ADAPT / DEFER / EXCLUDE)

### KEEP (copied verbatim under `ecc/`)
| Component | Why |
|---|---|
| `ecc/agents/` (20) + full catalog reference `docs/ECC-AGENTS.md` | Role knowledge; source of the registry |
| `ecc/skills/` (16), `ecc/commands/` (41), `ecc/rules/` (24) | Reusable procedures/rules underpinning playbooks |
| `ecc/schemas/` (10) | Contract/state shapes |
| `ecc/ecc2/` (Rust control plane), `ecc2.toml`, `agent.yaml` | Reference architecture + harness runner config |
| `ecc/integrations/aura/` | Zero-dep trust-gate adapter (real, runnable) |
| `ecc/research/ecc2-codebase-analysis.md` | Design rationale |
| `ecc/docs/` (curated) | Preserved documentation |

### ADAPT (reimplemented natively under `security_workforce/`)
Agent knowledge/roles (A,B), skills→playbooks (C,E,G), rules (D), research-first (I),
context/memory (J), verification gates (L), security tooling (O), auditability (T).

### DEFER / UNAVAILABLE (documented, not implemented)
Event/hook bus (N), parallel execution (P), full cost/context optimizer (Q), learning loop (R),
the continuous-assessment scheduler/trigger layer, and ECC `src/llm/` (see below). The validation
path via the hacker engine and 12 further agent adapters are now **implemented** (see
`security_workforce/README.md`); 7 capabilities remain honestly `UNAVAILABLE` for lack of an engine
primitive.

### EXCLUDE
Non-security agents (`seo-specialist`, `marketing-agent`); build resolvers and `gan-*`/`opensource-*`
tooling (infrastructure, not security roles); Claude-harness JS, plugins, MCP config, unrelated
translations/assets/examples; and, by construction, `.git`, secrets, `.env`, venvs, `node_modules`,
caches, build output.

---

## ecc2 (Rust control plane) decisions

| Concept | Decision | Why |
|---|---|---|
| Session state / worktree isolation | **ADAPT** | Task/result persistence is native today; isolation is a later scheduling concern |
| Task lifecycle / correlation | **ADAPT** | Reimplemented in `contracts.py` + orchestrator |
| Observability / structured results | **ADAPT** | Structured results + task/correlation IDs |
| Comms / events | **DEFER** | No event bus needed until the scheduler exists |
| Parallel execution / cancellation / retries | **DEFER** | Requires the async execution layer first |
| Command-execution boundaries | **REIMPL** | PurpleGuard already enforces its own tool/approval boundaries |
| TUI | **EXCLUDE** | Crate-internal; not a PurpleGuard surface |
| Whole Rust port | **EXCLUDE** | No cargo/rustc here; `ecc2.*` is honestly `ECC_UNAVAILABLE` through `ecc/bridge/` |

`ecc2` is preserved for reference and reached (if ever) through `ecc/bridge/` build-and-invoke, not
by translation.

---

## Agent-Reach

**BLOCKED / unavailable.** There is no `Agent-Reach/` directory in the audited ECC source
(`9c19aab`) and no references to one. It is **not fabricated** and no stub is created. If a real
source appears later it is a new, separately-reviewed extraction.

---

## ECC `src/llm/` provider layer

**DEFERRED, not extracted.** PurpleGuard already owns a working provider abstraction
(`agent_api/llm_provider.py`, `llm_client.py`). ECC's `src/llm/` was not copied and would only be
adopted later through a single controlled layer, never by replacement.

---

## Ownership boundary

- **PurpleGuard owns:** authentication, authorization, projects, assets, findings, evidence, attack
  paths, security state, developer workflow, approvals, remediation, verification, persistence,
  policy, UI, APIs, audit history.
- **The Security Workforce owns:** specialist reasoning, task execution, analysis, evidence
  collection, validation, recommendations, playbooks, coordinated agent activity.
- **ECC provides:** reusable knowledge, agent patterns, skills, rules, workflow/orchestration
  patterns, evaluation concepts, engineering patterns.

The workforce never becomes the authoritative security database, never modifies source, and never
bypasses PurpleGuard's approval gate.
