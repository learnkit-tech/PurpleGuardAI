# PurpleGuard AI — Audit & Development Plan

**Date:** 2026-09-24 · **Scope:** full repository audit, verified against source.
**Ground rule:** everything below marked ✅ was verified in code; anything marked
⚠️ is partial; anything marked ❌ does not exist in this repository and must not
be presented as built.

---

## 1. What PurpleGuard currently does

PurpleGuard today is a **working security-validation → remediation →
re-verification loop front end**, backed by Convex, designed to be driven by an
external Python engine. A user can sign in, browse findings produced by
authorized validation, follow an attack path to its evidence, open the affected
code, fix it manually or approve an AI-proposed patch through an explicit
approval gate, and have the real re-attack verdict recorded by the engine.

What it is **not** yet: a scanner (no discovery runs from the UI), a project
connector (no repo integrations), a defensive product (no blue team), or a
coordinated purple-team platform (no unified workflow state). The engine itself
(`orchestrator.py`, validator, remediation adapter) is **not in this repository** —
only the HTTP bridge the engine talks to.

Framework note: the product brief originally specified Next.js 15. The codebase
is **React 19 + Vite + React Router 7 + Convex** (Freebuff template constraint).
This is a deliberate, stable deviation; migrating frameworks is not recommended.

---

## 2. Architecture as it exists

```
/src
  pages/            Landing, Auth, Dashboard(=Console), HackerPanel,
                    DeveloperPanel, EccPanel, NotFound
  components/
    panels/         PanelShell (shared top bar + panel switcher)
    developer/      FindingWorkspace, ingest, engineFindings, seed/{sqli,rce,pathTraversal}
    landing/        marketing sections + mock console data
  hooks/            useAuth, useFindings, useApprovals, useRevalidation,
                    usePurpleGuardData (single shared derivation)
  convex/           schema, findings, approvals, revalidations, engineHttp,
                    http (routes), auth, users
  lib/              diff, utils
/docs               PANEL_ARCHITECTURE.md, ENGINE_API.md (this file's siblings)
```

Routes: `/` landing · `/auth` · `/dashboard` Console · `/hacker` · `/developer`
(+`/:findingId`) · `/ecc` — all auth-gated via `RequireAuth`.

Shared state: Convex tables **findings / approvals / revalidations**. All four
panels read through `usePurpleGuardData()`. Engine routes require
`X-Engine-Key`; UI mutations verify auth server-side.

---

## 3. WHAT EXISTS — verified working

| Capability | Where | Notes |
| --- | --- | --- |
| ✅ Auth (email OTP, anonymous, federated JWT) | `convex/auth*`, `Auth.tsx` | Server-side checks in every UI mutation/query |
| ✅ Findings persistence + ingest API | `convex/findings.ts`, `/api/ingest_finding` | Rejects payloads without `attackSteps` (no invented verdicts) |
| ✅ Approval queue → engine apply → verdict write-back | `convex/approvals.ts`, `/api/approvals/*` | Verdicts merge into finding `attackSteps` |
| ✅ Re-validation queue | `convex/revalidations.ts`, `/api/revalidate/*` | Powers "Re-run validation" |
| ✅ Engine bridge security | `engineHttp.ts` | `X-Engine-Key`, origin-restricted CORS, fail-closed |
| ✅ Developer workspace | `FindingWorkspace.tsx` | Evidence, code editor, diff, AI-fix proposal **with explicit approve gate**, manual save through the same approval gate, re-test (queues + "WAITING FOR ENGINE" when engine-backed), loop history |
| ✅ Hacker panel (display layer) | `HackerPanel.tsx` | Attack-path chains, surfaces, evidence dialog, **Send to Developer** (persists via `upsertFromUi`) |
| ✅ ECC panel (visibility layer) | `EccPanel.tsx` | Real work queues, pipeline stages, execution log; explicitly shows no agents ("not yet wired") |
| ✅ Main Console | `Dashboard.tsx` | Greeting, KPIs from real data, projects grid (derived from findings), Connect Project dialog, activity feed |
| ✅ Shared panel shell + switcher | `PanelShell.tsx` | Console/Hacker/Developer/ECC navigation |
| ✅ Landing page | `Landing.tsx` + sections | CTAs route into `/auth` → `/dashboard` |
| ✅ Seed findings (SQLi, RCE, path traversal) | `developer/seed/` | Carry recorded attack steps; verdict replay is labeled honestly |
| ✅ Docs | `docs/` | Engine API contract + panel responsibility matrix |

## 4. PARTIALLY WORKING

| Capability | Status | Gap |
| --- | --- | --- |
| ⚠️ Connect Project | GitHub OAuth live (repo picker → persisted project); manual registration works | GitLab/Bitbucket/local/upload are "soon"; no repo sync, PR flow, or push-triggered scans |
| ⚠️ "Start Validation" (Hacker) | Toast only | No scan/validation trigger; attack paths come from imported findings, not live discovery |
| ⚠️ Red-team loop (overall) | Display + handoff + re-test request exist end-to-end | Attack-surface discovery, attack-path *planning*, and validation *execution* all happen outside this repo; nothing here starts a run |
| ⚠️ Purple-team coordination | Panels share Convex state; verdicts propagate Console↔Hacker↔Developer↔ECC | No unified workflow state machine, no cross-team outcome tracking, no defensive linkage |
| ⚠️ AI fix generation | Proposal shown + gated | Patch comes from finding data (engine/seed); **no in-app LLM generation** |
| ⚠️ Mock/legacy data | Landing marketing console (intentional) | `developer/data.ts` still ships a duplicate legacy `DEVELOPER_FINDINGS` + legacy `runReTest` marker oracle alongside the current `seed/` + `engineFindings.ts` — duplication to remove |

## 5. NOT IMPLEMENTED (must never be shown as built)

- ❌ **Blue team / defensive protection — entirely absent.** No tables, no UI,
  no detections, no controls, no posture model, no mitigation mapping.
- ❌ **Purple-team layer as a product surface — absent.** Shared Convex state is
  the only cross-component connection today.
- ❌ **ECC as an orchestration engine.** No agent/task model, no execution
  engine, no event bus, no scheduling, no failure handling. Current ECC panel is
  read-only visibility of queues.
- ❌ **Project/repository connection (GitHub/GitLab/Bitbucket/local/upload).**
- ❌ **Scanner/analysis in-product** (static analysis, secret scanning, SCA, IaC).
- ❌ **Live attack-surface discovery / attack-path planning.**
- ❌ **First-class `projects` and workflow/run state tables.**
- ❌ Tests, CI, error boundaries per panel, onboarding flows.
- ❌ The Python engine itself in this repo (bridge + docs only).

## 6. Problems found

**Architecture**
- No `projects` entity — Console "projects" are a derived grouping of findings.
- No workflow/run state machine; status is inferred from table rows.
- Duplicate finding sources (legacy `data.ts` vs `seed/` vs Convex) and two
  `runReTest` implementations (legacy marker oracle still in tree).
- ECC designed as a *viewer* of queues, not yet an orchestrator — the seam
  between "visibility" and "coordination" is not yet formalized.

**Frontend**
- Dead-end buttons: `+ Connect Project` (GitHub) and `Start Validation` only toast.
- No per-panel loading/empty/error states beyond the basics; no tests.
- Landing console mock could be mistaken for the product by a casual reader.

**Backend / engine**
- Engine side (exporter, approvals poller, revalidate poller) is documented but
  lives outside the repo; nothing here verifies it runs.
- No webhook/event mechanism; panels rely on Convex reactive queries (fine, but
  run-level state has no home).
- `ENGINE_API_KEY` env var must be set or all engine routes 401 (fail-closed, by design).

**Red team** — discovery/planning/execution missing in-product; evidence is only
as real as the imported run; no scheduling, no scope/authorization artifacts.
**Blue team** — nothing exists. **Purple team** — no shared workflow states,
outcome model, or defensive mapping.

---

## 7. Success-criteria map (spec §14 steps)

| # | Step | Status |
| --- | --- | --- |
| 1–3 | Open · Connect · Select project | ⚠️ open ✅ / connect+select derived, no real connection |
| 4 | Start authorized validation | ⚠️ request can be queued for re-attack only; no fresh validation trigger |
| 5–7 | Surface → path → validate | ⚠️ surfaces/paths displayed from engine output; not generated here |
| 8 | Concrete finding produced | ✅ via engine ingest (bridge verified) |
| 9–10 | Developer opens finding + code | ✅ |
| 11–12 | Manual edit / AI fix, review diff, approve, apply | ✅ (approval gate verified) |
| 13–14 | Re-test → VERIFIED FIXED / STILL VULNERABLE | ✅ engine-backed (queue + write-back); seed replays recorded verdicts, honestly labeled |
| 15 | Result reflected in Main Console | ✅ (activity + verified %) |
| 16 | ECC orchestration | ⚠️ visibility of real queues only; no orchestration engine |
| 17 | Blue team evaluates/applies protections | ❌ not built |
| 18 | Purple-team coordination across teams | ❌ partial (shared state only) |

---

## 8. Development plan

### Phase 1 — Architecture foundations ✅ *(done 2026-09-24)*
**Was:** 4 panels, shared data hook, docs. **Done:** added `projects` and
`workflowRuns` tables (schema + Convex functions, auth-gated); findings ingest
now registers/touches the owning project; approvals/revalidations resolvers
touch the project; `PanelShell` gained a shared project selector backed by
`useProjectSelection` context; Hacker + Developer panels filter by the
selection; Hacker "Start Validation" now queues a **real** `workflowRun`
(presented honestly as queued, not executed — engine pickup is Phase 3);
removed the duplicate legacy finding fixture source and legacy marker-oracle
`runReTest`. **Still unbuilt after:** blue team, purple team, ECC engine,
repo connectors, run execution by the engine.
*Acceptance met:* every panel operates on the selected project; one finding
source; typecheck green.

### Phase 2 — Main Console ✅ *(done 2026-09-24; OAuth identity binding fixed 2026-09-25)*
**Was:** KPIs, activity, derived projects. **Done:** first-party GitHub OAuth
connect flow. **Fixed 2026-09-25:** the original implementation resolved the
PurpleGuard user inside the OAuth callback mutation via the Convex session —
but the callback is a top-level browser navigation to `*.convex.site`, which
carries **no Convex auth session**, so it always failed with
"Not authenticated". The flow now binds identity at mint time: the panel
calls the authenticated `github.beginConnection` mutation, which stores a
single-use state row bound to the user id **and** the app origin to return
to; the start route requires that state (400 without it); the callback
restores the user from the state row and 302s back to the stored origin's
`/dashboard?github=connected`. The panel redirects to the absolute
`<deployment>.convex.site/api/github/start` URL (relative URLs hit the app
origin, where HTTP routes do not exist). Daily cron cleans expired states.
The connect dialog states plainly that OAuth needs the deployment's
`GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` keys, and manual identifier
registration stays first-class. Token still stored only on the user row,
never sent to the client; repo picker registers projects with source
`github`; source badges (github/engine/handoff/manual); project detail page
with per-surface status, run history, attack paths. **Still unbuilt after:**
OAuth credentials themselves are not yet set on the deployment (add
`GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` via the Keys tab — the flow is
fail-closed until then); GitLab/Bitbucket/local/upload connectors; repo sync
beyond registering the project (no push/PR/branch integration yet).

### Phase 3 — Hacker / red team completion ✅ *(bridge done 2026-09-24; execution lives in the engine repo)*
**Was:** chains, surfaces, evidence display, handoff, re-attack queueing; runs
were recorded intent only. **Done:** runs are now **real executable work** —
engine routes `/api/runs/pending` (list queued), `/api/runs/claim` (atomic
claim; response carries the run's **scope** — authorized/blocked path
artifacts the engine must respect), `/api/runs/resolve` (outcome +
`findingsIngested` count); "Start Validation" (Hacker panel + project detail)
queues a run with a scope the user edits in a dialog; Runs tab in the Hacker
panel shows status, scope, notes, and ingested counts; daily Convex cron
queues de-duped re-validation runs per project. **Added 2026-09-25:**
`scripts/engine-client.mjs` — a minimal honest reference client demonstrating
the full runs contract (poll → claim → scope → resolve; dry-run mode resolves
`ok:false` and never fabricates results). **Still unbuilt after:** discovery,
planning, and validation execution themselves run in the engine repo —
nothing here scans; the engine must implement the runs flow against
docs/ENGINE_API.md §6–8 (the reference client shows the exact contract).

### Phase 4 — Developer workspace completion
**Have:** full loop. **Do:** project-scoped findings, keyboard/routing polish,
persist workspace buffer per finding (server-side), real AI fix generation
behind the existing approve gate (LLM call server-side; verdict still engine-only).

### Phase 5 — Blue team (future — label as such everywhere)
Design first, then build: `defenses`/`detections`/`posture` tables; mapping
confirmed findings → recommended controls; defensive status per project;
defensive verification. **Nothing here exists; every UI element must be marked
"planned" until it lands.**

### Phase 6 — ECC orchestration
**Have:** queue visibility. **Do:** task/execution model in Convex; ECC consumes
workflow events (run started, finding confirmed, fix approved, retest result)
and exposes task state to the ECC panel; failure/error surfaces. Agents appear
in the UI **only** when real orchestration exists to back them.

### Phase 7 — Purple-team coordination
Shared workflow state machine across all surfaces; outcome tracking
(offensive finding → fix → verification → defensive control → closed);
cross-panel timeline; reporting.

### Phase 8 — End-to-end proof
Scripted acceptance run: connect → validate → finding → fix → approve → apply
→ re-test → verified → console reflects it. **Currently steps 1–4 and 16–18 are
the gap; do not claim E2E until Phase 1–7 land.**

### Phase 9 — Polish (only after function)
Loading/empty/error states per panel, onboarding, responsiveness, visual pass.

---

## 9. Risks / unknowns
- Engine-side repo is out of scope here; bridge changes require coordinated
  engine updates (docs/ENGINE_API.md is the contract).
- GitHub OAuth needs app credentials + token storage decisions.
- Framework deviation (Vite vs Next.js) is permanent unless the team decides
  otherwise — reconfirm before any migration work.
- No tests exist; Phase 1 should add at least ingest/verify-loop unit tests
  before refactors.
