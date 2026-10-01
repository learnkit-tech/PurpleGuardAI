# ECC ↔ PurpleGuard Integration

**Provenance:** curated snapshot from ECC commit `9c19aabe0f6506a4d0f47945e3f6cae59d7e4e7c`
(`learnkit-tech/ECC`). This is a curated ECC snapshot extracted into PurpleGuardAI; the upstream ECC
repository remains separate and untouched. Companion docs:
[`ECC_EXTRACTION_MANIFEST.md`](ECC_EXTRACTION_MANIFEST.md),
[`ECC_CAPABILITY_MAP.md`](ECC_CAPABILITY_MAP.md),
[`ECC_AGENT_WORKFORCE.md`](ECC_AGENT_WORKFORCE.md).

---

## Architecture

```
┌──────────────────────────────────────────────┐
│                PURPLEGUARD AI                 │  product + security authority
│   projects · auth · findings · evidence ·     │
│   approvals · remediation · verification ·    │
│   security state · UI · backend               │
└───────────────────┬──────────────────────────┘
                    │  imports only these two surfaces
        ┌───────────┴─────────────┐
        ▼                         ▼
┌───────────────────┐   ┌────────────────────────────┐
│  security_workforce│   │        ecc/bridge/          │
│  (PurpleGuard-     │   │  runtime capabilities of    │
│   native agents,   │   │  the ECC snapshot           │
│   playbooks,       │   │  (snapshot, harness, eval,  │
│   evaluation,      │   │   aura trust check)         │
│   correlation)     │   └────────────┬───────────────┘
└─────────┬──────────┘                │
          │                           ▼
          │                    ┌──────────────┐
          │                    │  ecc/  snapshot│  vendored source (provenance)
          │                    │  agents · skills│
          │                    │  rules · ecc2   │
          │                    └──────────────┘
          ▼
   scanner/ · hacker/ · purpleguard_runner.py   ← security execution (authoritative)
```

- **PurpleGuard** owns security state, authorization, approval, remediation and verification.
- **`security_workforce/`** is PurpleGuard-native; it depends on no ECC internals.
- **`ecc/bridge/`** is the only surface that may touch the snapshot, and only for runtime
  capabilities.
- **`ecc/`** is vendored source kept for provenance and future extraction.

## Communication boundaries

| Boundary | Rule |
|---|---|
| PurpleGuard → snapshot | Only via `ecc/bridge/`. A test forbids `from ecc`/`import ecc` anywhere outside `ecc/`, `tests/`. |
| PurpleGuard → workforce | Only via `security_workforce` public API (`WorkforceOrchestrator`, contracts). |
| Workforce → PurpleGuard tools | Only through `security_workforce/adapters/` (e.g. `scanner.py`). |
| Agents → security state | Structured `AgentResult` only; nothing unstructured becomes authoritative. |
| Agents → source modification | Forbidden. No agent holds `modify`; changes stay behind `purpleguard_runner.py --approve`. |

## Contracts crossing the boundary

**Task:** `task_id`, `correlation_id`, `project_id`, `operation`, `input`, `playbook`, `timeout`,
`idempotency_key`, `metadata`, `created_at`. IDs are deterministic.

**Agent result:** `agent_id`, `task_id`, `correlation_id`, `role`, `status`, `findings`, `evidence`,
`recommendations`, `confidence`, `errors`, `metadata`.

**Structured errors:** `{code, message, detail}` with codes `UNSUPPORTED_OPERATION`, `REJECTED`,
`INVALID_TASK`, `ECC_UNAVAILABLE`, `MALFORMED_RESULT`, `EXECUTION_ERROR`, `TIMEOUT`,
`TASK_NOT_FOUND`. Fail-closed: an unavailable capability is an explicit error, never a silent
success.

## Workflow the workforce feeds (existing Phase 4.1 loop, unchanged)

```
authorized target → recon → attack paths → dynamic validation → evidence
  → finding → developer handoff → approval → remediation → re-test → verification
```

The workforce **produces** findings + evidence and **consumes** prior context; PurpleGuard's existing
evidence/remediation/re-test flow stays authoritative and is not replaced.

## Security boundaries enforced

Least privilege · explicit tool permissions · approval gates · fail-closed behavior ·
evidence-first findings · auditability · provenance · no secret leakage · no fabricated evidence or
agents · no silent production modification · no bypass of authentication, authorization, or
remediation approval.

## What is executable today vs. planned

- **Executable:** 13 capabilities backed by real engine adapters — the static scanner (full and
  rule-filtered), the project analyzer, the hacker static analyzer, the dynamic validation engine,
  the verification engine, the native quality gate, and orchestration over real state. Multi-agent
  `assess`, canonical correlation/dedupe, context, persistence, deterministic IDs, and the
  developer handoff (approval → remediation → re-test → verification) are all real.
- **Bridge runtime capabilities:** snapshot catalog, harness describe, `agent.evaluate`,
  AURA trust check; `ecc2.*` honestly `ECC_UNAVAILABLE`.
- **Unavailable (not faked):** 7 capabilities with no engine path (architect, spec-miner,
  network-architect, network-config-reviewer, network-troubleshooter, loop-operator,
  harness-optimizer), and the continuous-assessment scheduler.
