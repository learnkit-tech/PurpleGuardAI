# ECC → PurpleGuard Extraction Manifest

**Status:** Phase 0 + Phase 1 complete · Phase 2 (this document) complete · extraction not started.
**Rule in force:** no ECC files are copied, no PurpleGuard functionality is removed, and ECC is
**not** deleted until extraction is verified and explicitly approved.

---

## 1. Decision and provenance

PurpleGuardAI is the final product. ECC is a **source of capabilities**, not a second product to
maintain independently. The objective is a deliberate, documented ECC subsystem inside PurpleGuard,
not a blind merge and not a wholesale copy.

| Field | Value |
|---|---|
| ECC upstream | `affaan-m/ECC` — "Everything Claude Code", MIT, v2.0.0 |
| ECC being audited | `learnkit-tech/ECC` (fork used by this workspace) |
| Audited commit | `9c19aab` — "fix(ecc2): make purpleguard harness runner host-portable" (branch `main`) |
| Working copy | `/tmp/ecc-work` (tracked files: 3,265) |
| PurpleGuard | `/home/daytona/codebase`, branch `master`, HEAD `8e05929` |
| PurpleGuard → ECC touchpoints today | `ecc2.toml` + `ecc2/ecc2.toml` only (the `[harness_runners.purpleguard]` runner) |

ECC is a fork of an upstream project. Anything extracted must be documented here (origin path,
license, and why) so a future developer can tell copied code from PurpleGuard code.

---

## 2. What ECC actually contains (measured at `9c19aab`)

ECC is overwhelmingly a **markdown agent-harness library** with three pockets of real executable code.

| Area | Files | Kind | Reality |
|---|---:|---|---|
| `docs/` | 1,496 | markdown | Mostly translations (es/pt/zh/ja/…) + guides |
| `skills/` | 441 (271 `SKILL.md`) | markdown (+ a few helper `.py`) | Prompt/skill catalog |
| `scripts/` | 209 (377 `.js` total repo-wide) | Node/JS | Claude-harness hooks, CI validators, catalog build |
| `tests/` | 179 | JS + a little Python | Tests for the hook/CI/skill surface, plus `src/llm` + `aura` Python tests |
| `rules/` | 114 | markdown | Per-language coding rules |
| `commands/` | 92 | markdown | Slash-command definitions |
| `agents/` | 67 | markdown | Agent role definitions |
| `ecc2/` | 21 (**16 `.rs`, 52,139 lines**) | **Rust — real code** | ECC 2.0 control plane (alpha) |
| `src/llm/` | 20 (**1,490 lines**) | **Python — real code** | Provider abstraction (claude/openai/ollama/atlas/astraflow) |
| `integrations/aura/` | 7 | **Python — real code** | Zero-dependency read-only trust-gate adapter + tests + threat model |
| `schemas/`, `manifests/`, `config/`, `contexts/`, `hooks/`, `mcp-configs/`, `plugins/` | ~35 | JSON/MD | Install/config/hook contracts and examples |

File-type breakdown (tracked): `2469 md · 377 js · 110 json · 61 py · 41 yaml · 32 sh · 18 ts · 16 rs · 12 mjs · 10 toml · 3 tsx`.

### Important corrections to the task brief

1. **`Agent-Reach/` does not exist** in this ECC checkout. No file references "Agent-Reach" or
   "agent-reach". Phase 11 is therefore **not applicable** until a source for it is provided.
2. **There is no Python orchestrator/planner/evaluator/validator/queue/worker implementation** in
   ECC. Those concepts exist as:
   - **markdown** agent/skill/command definitions (`orch-*`, `plan-*`, `multi-*`, `epic-*`), and
   - the **`ecc2/` Rust control plane** (sessions, daemon, worktree, observability), which is
     Claude-Code-harness oriented and self-described as **alpha**.
3. `ecc2/README.md` and `research/ecc2-codebase-analysis.md` are partially **stale**
   (the research doc says `main.rs` is 142 lines; it is now 12,595; ecc2 is ~12× larger now).

---

## 3. Component inventory and disposition

Legend: **EXTRACT** (copy into `ecc/`) · **ADAPT** (copy + modify) · **INTEGRATE** (wire into
PurpleGuard) · **REPLACE** (PurpleGuard already owns it) · **ARCHIVE** (keep for reference only) ·
**NOT NEEDED**.

### 3.1 Executable code

| ECC source | Purpose | Status / deps | Tests | PurpleGuard equivalent | Disposition |
|---|---|---|---|---|---|
| `ecc2/src/session/{store,runtime,manager,daemon,output}.rs` | Session lifecycle, SQLite store, DbWriter thread, daemon timeout loop, ring-buffer output | Real, alpha; rusqlite/tokio | 12 targeted tests | `dev_agent/{autonomous_loop,task_runner,worker,progress}.py` (no persistence/daemon) | **ADAPT / INTEGRATE** (session store + lifecycle as reference for a real ECC session table) |
| `ecc2/src/observability/mod.rs` | 4-axis tool-call **risk scoring** → Allow/Review/RequireConfirmation/Block | Real | 5 | `dev_agent/decision.py` (much simpler) | **INTEGRATE** (risk model is directly useful for approval gating) |
| `ecc2/src/worktree/mod.rs` | Git worktree create/merge/rebase/health | Real (2.7k lines) | 0 | `dev_agent/git_manager.py` | **ADAPT** (reference; PG uses a simpler git flow) |
| `ecc2/src/comms/mod.rs` | Inter-agent messages (TaskHandoff/Query/Response/Conflict) | **Send-only** — no receive/poll | 0 | none | **ADAPT** (add the receive side before integrating) |
| `ecc2/src/config/mod.rs` | TOML config, risk/budget thresholds, agent profiles | Real | 5 | none | **ADAPT** (mirror thresholds in PG config) |
| `ecc2/src/notifications.rs` | Webhook/desktop completion notifications | Real | — | none | **EXTRACT / INTEGRATE** (opt-in notifier) |
| `ecc2/src/tui/*` | Terminal dashboard | Real | 11 | `frontend/` (Next.js) | **ARCHIVE** (PG has its own UI) |
| `ecc2/src/main.rs` | CLI | Real (12.6k lines) | 1 | `main.py`, `purpleguard_cli.py` | **ARCHIVE** (harness-specific) |
| `src/llm/{core,providers,prompt,tools,cli}` | Provider abstraction + prompt builder + tool executor | Real; deps `openai`, `anthropic`, stdlib | `tests/test_*_provider.py`, `test_resolver`, `test_executor`, `test_types`, `test_builder` | `agent_api/{llm_provider,llm_client}.py` (thin) | **ADAPT / INTEGRATE** (strongest near-term win; decide adopt-vs-reference, §9) |
| `integrations/aura/adapter.py` (+ tests, THREAT_MODEL) | Read-only, fail-closed counterparty trust gate; zero-dep | Real, self-contained | `integrations/aura/tests/` | none | **EXTRACT** as `ecc/integrations/aura/` (opt-in; template for external trust gating) |
| `scripts/hooks/*.js`, `scripts/ci/*.js` | Claude-harness hooks + validators | Real but harness-specific (Node) | `tests/hooks`, `tests/ci` | none | **ARCHIVE** (ideas only: `validate-no-personal-paths`) |
| `ecc_dashboard.py` | Tkinter GUI | Real | — | `frontend/` | **NOT NEEDED** |

### 3.2 Catalogs (markdown capability definitions)

| ECC source | Count | Disposition |
|---|---:|---|
| `skills/` | 271 `SKILL.md` | **EXTRACT curated subset** (security, orchestration, verification, eval, budget); rest **ARCHIVE** |
| `agents/` | 67 | **EXTRACT curated subset** (see below); rest **ARCHIVE** |
| `commands/` | 92 | **EXTRACT curated subset** (`orch-*`, `multi-*`, `plan*`, `quality-gate`, `security-scan`, `checkpoint`, `*-session`, `loop-*`, `harness-audit`, `epic-*`, `evolve`, `santa-loop`); rest **ARCHIVE** |
| `rules/` | 114 | **EXTRACT** `common`, `python`, `web`; other languages **NOT NEEDED** |
| `docs/` | 1,496 | **EXTRACT** `architecture/`, `ECC-2.0-REFERENCE-ARCHITECTURE.md`, `SESSION-ADAPTER-CONTRACT.md`, `cross-harness.md`, `observability-readiness.md`; translations **NOT NEEDED** |
| `hooks/`, `mcp-configs/`, `plugins/`, `contexts/` | ~15 | **ARCHIVE** (Claude-Code runtime; PG has a different runtime) |
| `schemas/` | 10 | **EXTRACT** as contract reference (`state-store`, `provenance`, `hooks`, `install-*`) |
| `manifests/`, `config/` | 5 | **ARCHIVE** (install distribution metadata) |
| `research/ecc2-codebase-analysis.md` | 1 | **EXTRACT** (useful, with a "stale" note) |

Curated `agents/` subset: `security-reviewer`, `planner`, `architect`, `code-reviewer`,
`agent-evaluator`, `loop-operator`, `tdd-guide`, `spec-miner`, `e2e-runner`, `python-reviewer`,
`harness-optimizer`.

Curated `skills/` seed set: `security-review`, `security-scan`, `verification-loop`, `agent-eval`,
`eval-harness`, `agent-self-evaluation`, `continuous-agent-loop`, `autonomous-loops`,
`plan-orchestrate`, `tdd-workflow`, `context-budget`, `token-budget-advisor`, `python-testing`,
`python-patterns`, `error-handling`, `search-first`.

---

## 4. Disposition summary

- **EXTRACT (curated):** `integrations/aura/`, `schemas/`, `research/`, a curated `skills/`,
  `agents/`, `commands/`, `rules/`, `docs/` subset, curated `ecc2/` source + `src/llm/`.
- **ADAPT:** `ecc2` session store/observability/worktree/config/notifications; `comms`;
  `src/llm` provider layer.
- **INTEGRATE:** risk-scoring gate, notifications, session/execution state, bridge, ECC panel/backend.
- **REPLACE by PurpleGuard (do not duplicate):** planner, task routing, memory, LLM client, agent
  tools, dashboard/UI, CLI, remediation approval gate.
- **ARCHIVE / NOT NEEDED:** `ecc2/tui`, `ecc_dashboard.py`, hook/CI JS, language rules other than
  Python/web, docs translations, install manifests.

---

## 5. Target `ecc/` layout (Phase 3)

```
ecc/
├── README.md                 # what ECC is + why it lives here (Phase 6)
├── AGENTS.md                 # curated agent catalog note
├── MANIFEST.json             # machine-readable copy of this table (provenance/sha256 per file)
├── agents/                   # curated markdown agent roles
├── skills/                   # curated SKILL.md subset
├── commands/                 # curated slash-command definitions
├── rules/                    # common + python + web
├── docs/                     # curated architecture/contract docs + research/
├── schemas/                  # extracted JSON contracts
├── integrations/
│   └── aura/                 # extracted adapter + tests + THREAT_MODEL
├── ecc2/                     # extracted Rust control plane (ecc2/src subset + Cargo files)
├── src/
│   └── llm/                  # extracted Python provider layer
├── bridge/                   # NEW: the only import surface PurpleGuard may use (Phase 7)
└── tests/                    # extraction-integrity + bridge tests
```

Create only directories that receive real content. `MANIFEST.json` records, for every extracted
file: ECC source path, destination path, sha256, license/origin, and disposition.

---

## 6. Extraction rules and exclusions (Phase 4)

Never copy: `.git/`, credentials, API keys, secrets, `.env*`, virtualenvs, `node_modules/`, caches,
generated artifacts, build output, OS/temp files, translations that are not needed.

Preserve: license headers, `LICENSE`, origin attribution, and any `THREAT_MODEL.md`/contract docs.

Scan after copying (Phase 5): compare source tree vs `ecc/`, verify no secrets, no absolute personal
paths (ECC ships `validate-no-personal-paths`), no dangling imports, and that `ecc/` is reproducible
from `MANIFEST.json`.

---

## 7. Avoid duplication — PurpleGuard already owns these

PurpleGuard already provides: `dev_agent/{planner,autonomous_planner,task_router,task_runner,tasks_executor,worker,memory,progress,roadmap_manager,self_corrector,patcher,git_manager,change_manager,code_generator,coder,decision,local_brain,prompt_builder}.py`,
`agent_api/{executor,llm_client,llm_provider,permissions,tools}.py`, `api/server.py`,
`frontend/`, and the security engine (`scanner/`, `hacker/`, `purpleguard_runner.py`).

Extraction must **reuse** these rather than introduce ECC parallels. Where ECC's version is better
(e.g. `src/llm` provider routing, `observability` risk scoring), adapt ECC's version **into** the
existing PurpleGuard module — do not create a competing one.

---

## 8. Integration order (Phases 5–27)

1. Extract + verify (Phases 3–5) — produce `ecc/` + `MANIFEST.json`, no wiring.
2. `ecc/README.md` + `docs/ECC_INTEGRATION.md` (Phase 6).
3. `ecc/bridge/` controlled interface — the **only** import surface for PurpleGuard (Phase 7).
4. Task contract + result contract + event system (Phases 16–18).
5. Observability/risk + notifications + session/execution state (Phases 8, 14).
6. Agent system + ECC panel backed by **real** backend state (Phases 9, 13).
7. ECC2 / Agent-Reach evaluation (Phase 10; Phase 11 blocked — see §9).
8. End-to-end (Phase 25) including the honest clean-target branch (Phase 22) and failure paths (Phase 23).
9. Documentation + retirement report (Phases 26–27). Retirement itself requires explicit approval (Phase 28).

Approval gate stays: an autonomous agent must **never** silently modify source. PurpleGuard
independently enforces its own boundaries (Phases 19, 21).

---

## 9. Risks, blockers, and decisions needed

- **BLOCKER — ECC git push denied:** `Permission to learnkit-tech/ECC.git denied to freebuff-web[bot]`
  (HTTP 403). The ECC fork's commit `9c19aab` cannot be pushed from this workspace. Reconnect
  `learnkit-tech/ECC` / grant the Freebuff GitHub App access. No credential workaround will be used.
- **BLOCKER — Agent-Reach absent** (Phase 11 cannot proceed; needs a source).
- **Decision needed:** adopt ECC's `src/llm` provider abstraction **as** PurpleGuard's
  `agent_api/llm_provider.py` (one provider layer), or extract it as reference and keep the existing
  thin client? (Recommend: single provider layer via the bridge.)
- **Decision needed:** ECC2 is Rust and alpha. Integrate by **building the binary and calling it
  through the bridge**, or port only the useful session/observability logic to Python? (Recommend:
  bridge to the binary; do not port Rust for convenience.)
- **Risk:** ecc2's `comms` is send-only and `worktree`/`comms` have no tests — do not present them
  as operational.
- **Risk:** `build_configured_harness_command` passes `base_args` verbatim (already addressed in
  `9c19aab`); keep the runtime-discovery bootstrap.
- **Scale:** `ecc/` must stay a **curated** subtree. Copying all 2,469 markdown files would bury the
  signal and duplicate upstream docs.
- **Licensing/attribution:** ECC is MIT (upstream `affaan-m/ECC`); preserve `LICENSE` and record
  origin in `MANIFEST.json`.

---

## 10. Acceptance checklist (from the task)

Audit ✅ · important files identified ✅ · extraction manifest ✅ (this doc) · `ecc/` tree ⬜ ·
extracted material ⬜ · secrets excluded ⬜ · docs preserved ⬜ · ECC2 evaluated ✅ (audited,
disposition ADAPT/ARCHIVE) · Agent-Reach evaluated ⚠️ (absent) · agent/orchestration evaluated ✅ ·
bridge ⬜ · panel real state ⬜ · backend real state ⬜ · security engine intact ✅ (untouched) ·
red-team/developer/approval/remediation/re-test/verification ⬜ (existing, to be re-verified) ·
clean branch ⬜ · failure paths ⬜ · existing tests ✅ (124 passed / 2 skipped at `8e05929`) ·
integration tests ⬜ · E2E ⬜ · docs ⬜ · ECC untouched ✅ · no fake functionality ✅ · no secrets
committed ✅.
