# ECC agents (curated) — inside PurpleGuardAI

This is a **curated subset (20 of 67)** of ECC's agent role definitions, preserved as the foundation
of PurpleGuard's Security Agent Workforce. It is not PurpleGuard's own agent configuration.

Full analysis and role mapping: [`../docs/ECC_AGENT_WORKFORCE.md`](../docs/ECC_AGENT_WORKFORCE.md).

## Boundary rules

- These are **role definitions (markdown), not executable agents.** An agent is not "available"
  until it has a real adapter; otherwise it is `defined_only`.
- PurpleGuard owns security state, authorization, and the approval gate; agents only observe,
  analyze, and (later) validate/propose/verify. **No agent is granted `modify`.**
- Reaching any ECC capability at runtime must go through `ecc/bridge/`.
- ECC must never be the authority that approves source modification.

## Extracted agents (20)

| Agent | PurpleGuard category | Autonomy | Adapter |
|---|---|---|---|
| `security-reviewer` | vulnerability_analysis | autonomous | **available** |
| `database-reviewer` | vulnerability_analysis | autonomous | defined_only |
| `mle-reviewer` | vulnerability_analysis | autonomous | defined_only |
| `network-config-reviewer` | vulnerability_analysis | autonomous | defined_only |
| `code-explorer` | reconnaissance | autonomous | defined_only |
| `comment-analyzer` | reconnaissance | autonomous | defined_only |
| `spec-miner` | reconnaissance | autonomous | defined_only |
| `network-architect` | reconnaissance | autonomous | defined_only |
| `code-reviewer` | validation | autonomous | defined_only |
| `python-reviewer` | validation | autonomous | defined_only |
| `network-troubleshooter` | validation | autonomous | defined_only |
| `silent-failure-hunter` | validation | autonomous | defined_only |
| `e2e-runner` | validation | autonomous | defined_only |
| `agent-evaluator` | verification | autonomous | defined_only |
| `tdd-guide` | verification | approval_required | defined_only |
| `architect` | orchestration | autonomous | defined_only |
| `planner` | orchestration | autonomous | defined_only |
| `chief-of-staff` | orchestration | autonomous | defined_only |
| `loop-operator` | orchestration | autonomous | defined_only |
| `harness-optimizer` | orchestration | approval_required | defined_only |

The full ECC catalog (67 agents) is upstream; the remaining 47 are classified in the workforce doc
(adapt later / infrastructure-only / excluded). ECC's original full agent instructions are preserved
at `docs/ECC-AGENTS.md`.
