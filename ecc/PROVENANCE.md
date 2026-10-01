# ECC extraction provenance

Every file under `ecc/` (except the PurpleGuard-authored files listed below) was extracted verbatim
from the ECC repository at one pinned revision.

## Source

| Field | Value |
|---|---|
| Source repository | `learnkit-tech/ECC` (fork) |
| Upstream project | ECC — "Everything Claude Code", `affaan-m/ECC` |
| Branch | `main` |
| Commit | `9c19aabe0f6506a4d0f47945e3f6cae59d7e4e7c` |
| Commit subject | `fix(ecc2): make purpleguard harness runner host-portable` |
| Commit date | `2026-09-23T08:33:34+00:00` |
| License | MIT — Copyright (c) 2026 Affaan Mustafa (see [`LICENSE`](./LICENSE)) |
| Extraction method | `git -C <ecc> archive HEAD -- <paths> \| tar -x -C ecc/` (tracked files only) |
| Upstream repo modified? | **No** (read-only `git archive`) |

Because `git archive` exports only tracked files, no `.git`, secrets, virtualenvs, `node_modules`,
caches, or build output can be present in the export.

## PurpleGuard-authored files (not from ECC)

- `ecc/README.md` (this directory's guide)
- `ecc/PROVENANCE.md` (this file)
- `ecc/AGENTS.md`
- `ecc/MANIFEST.json`
- `ecc/CHECKSUMS.sha256`
- `ecc/bridge/README.md`

`ecc/docs/ECC-AGENTS.md` is ECC's original `AGENTS.md`, moved under `docs/` to avoid it being read
as PurpleGuard's own agent instructions.

## Components extracted (with original ECC paths)

See [`MANIFEST.json`](./MANIFEST.json) for the complete, machine-readable mapping
(source path → destination → disposition → reason → dependencies → integration method).

## Not extracted (see MANIFEST.json `excluded` / `deferred`)

- `src/llm/` — DEFERRED (Decision A: PurpleGuard keeps its own provider layer).
- `docs/` translations and the non-`common`/`python`/`web` rule packs.
- Claude-harness JS hooks, CI validators, install manifests, plugin/mcp configs, TUI-only assets,
  `ecc_dashboard.py`, `node_modules`/build output.
- The remaining ~230 skills and ~56 agent/command definitions not selected.
