# ECC (extracted subset) — inside PurpleGuardAI

This directory is a **curated, reversible extraction** of capabilities from the ECC project
("Everything Claude Code", upstream `affaan-m/ECC`), vendored into PurpleGuard so future
PurpleGuard development can reuse ECC's agent/orchestration material without depending on the
external ECC repository.

It is **not** a copy of ECC. It is **not** PurpleGuard's own code. Everything here is attributed to
ECC and pinned to one revision (see [`PROVENANCE.md`](./PROVENANCE.md) and
[`MANIFEST.json`](./MANIFEST.json)).

## Why this exists

PurpleGuardAI is the product. ECC is a source of reusable agent/orchestration capabilities. This
subtree preserves exactly the ECC material that PurpleGuard may need, with provenance, so it can be
traced, re-extracted, or removed.

## Architecture decisions (recorded, not implied)

**Decision A — LLM provider layer: PurpleGuard keeps ownership; ECC `src/llm/` is NOT extracted.**
PurpleGuard already owns `agent_api/llm_provider.py` and `agent_api/llm_client.py`. Replacing them
would replace working infrastructure merely because ECC has an alternative, which the extraction
rules forbid. ECC's provider abstraction (`src/llm/`, 1,490 lines) stays in the source repository
and is recorded as **DEFERRED** in `MANIFEST.json`; adopting it later must go through
`ecc/bridge/`, one provider layer at a time.

**Decision B — integration is through a bridge, not by porting.**
ECC capabilities are reached through the controlled interface in [`bridge/`](./bridge/), not by
copying ECC logic into PurpleGuard modules. PurpleGuard's security engine
(`scanner/`, `hacker/`, `purpleguard_runner.py`) stays authoritative. The `ecc2/` Rust control
plane is to be **built and bridged**, not ported to Python (Decision B in the manifest).

## What is here

| Path | What | Disposition |
|---|---|---|
| `ecc2/` | ECC 2.0 Rust control plane (session store, observability/risk scoring, worktree, comms, config, notifications, TUI) | EXTRACT (source; build + bridge) |
| `ecc2.toml`, `agent.yaml` | ECC harness config + agent/skill manifest | EXTRACT |
| `integrations/aura/` | Zero-dependency, fail-closed counterparty trust-gate adapter (+ tests, threat model) | EXTRACT |
| `agents/` | 11 curated agent role definitions (markdown) | EXTRACT |
| `skills/` | 16 curated skills (markdown + helper assets) | EXTRACT |
| `commands/` | 41 curated command definitions (orchestration, planning, security, sessions) | EXTRACT |
| `rules/` | `common`, `python`, `web` coding/security rules | EXTRACT |
| `schemas/` | ECC JSON schemas (state store, provenance, hooks, install) | EXTRACT |
| `docs/` | Curated architecture + contract docs, plus ECC's `AGENTS.md` | EXTRACT |
| `research/` | ECC's own ecc2 codebase analysis (with a "stale" caveat) | EXTRACT |
| `bridge/` | Controlled interface spec — the **only** surface PurpleGuard should import from | NEW (spec only) |

## How to use / modify

- Treat this tree as **read-mostly vendored content**. Prefer changing PurpleGuard modules and the
  bridge over editing files here.
- If ECC must be re-synced, use `MANIFEST.json` (source paths + pinned commit) and regenerate
  `CHECKSUMS.sha256` (see below). Do not hand-edit the vendored files.
- Runtime is **Python/Node**; `ecc2/` is Rust and is not built as part of PurpleGuard's Python
  package (PurpleGuard's `pyproject.toml` packages only `scanner*` and `hacker*`).

## Verification

- `ecc/CHECKSUMS.sha256` pins every extracted file.
- `tests/unit/test_ecc_extraction.py` checks the tree is present, attributed, and free of secrets.
- Regenerate checksums after an intentional re-sync:
  `find ecc -type f ! -name CHECKSUMS.sha256 | sort | xargs sha256sum > ecc/CHECKSUMS.sha256`

## Status

Extracted and verified only. **No PurpleGuard module imports `ecc/` yet** — bridge and backend
integration are the next phase. Nothing in upstream ECC was modified.
