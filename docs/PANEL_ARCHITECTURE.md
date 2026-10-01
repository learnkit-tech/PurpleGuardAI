# PurpleGuard Panel Architecture

PurpleGuard is four connected surfaces with **distinct responsibilities** —
not four copies of the same dashboard. This document is the contract any UI
change must respect.

```
PURPLEGUARD AI
                      │
        ┌─────────────┼─────────────┐
        ▼             ▼             ▼
      HACKER      DEVELOPER     PROJECTS (Console)
        │             │
        └──────┬──────┘
               ▼
              ECC          ← orchestration layer (under all surfaces)
               │
         ┌─────┼─────┐
         ▼     ▼     ▼
      Validate Fix  Verify
```

---

## Surfaces

| Surface | Route | File | Question it answers |
| --- | --- | --- | --- |
| **Main Console** | `/dashboard` | `src/pages/Dashboard.tsx` | "What projects do I have, and what is their security state?" |
| **Hacker** | `/hacker` | `src/pages/HackerPanel.tsx` | "How can this application actually be attacked, and can we prove it?" |
| **Developer** | `/developer` (+ `/developer/:findingId`) | `src/pages/DeveloperPanel.tsx` | "Show me the vulnerable code and let me fix and verify it." |
| **ECC Control** | `/ecc` | `src/pages/EccPanel.tsx` | "What is PurpleGuard's machinery doing underneath?" |

All four share `src/components/panels/PanelShell.tsx` (brand, panel switcher,
account menu) and `src/hooks/usePurpleGuardData.ts` (one derivation of the
real data).

---

## Responsibility matrix

| Function | Console | Hacker | Developer | ECC |
| --- | :-: | :-: | :-: | :-: |
| Connect GitHub / project | ✅ | ❌ | ❌ (secondary only) | ❌ |
| Project selection | ✅ | context | context | context |
| Security overview KPIs | ✅ | — | — | — |
| Discover attack surfaces | — | ✅ | — | — |
| Attack paths | summary | ✅ | finding context | orchestrates |
| Exploit validation | summary | ✅ | verification result | orchestrates |
| View vulnerable code | — | context | ✅ | — |
| Edit code | ❌ | ❌ | ✅ | ❌ |
| AI-generated fix | ❌ | ❌ | ✅ | supports |
| Approve fix | ❌ | ❌ | ✅ | ❌ |
| Re-test | trigger | ✅ | ✅ | orchestrates |
| Agents / tasks | ❌ | ❌ | ❌ | ✅ |
| Logs | activity | evidence | activity | detailed |

---

## The user journey (the product)

1. **Connect my project** — Console, `+ Connect Project`
2. **PurpleGuard validates it** — engine run; findings land in Convex
3. **Show me what can actually be exploited** — Hacker, attack paths with evidence
4. **Take me to the vulnerable code** — Hacker → Developer handoff
5. **Fix it myself, or let PurpleGuard propose a fix** — Developer workspace
6. **I approve the change** — explicit approve gate (ECC patch or manual save)
7. **PurpleGuard tests it again** — re-attack queued; ECC orchestrates
8. **"Verified fixed"** — only from the engine's real re-attack

---

## Data flow (single source of truth)

- `projects` table — first-class project entity. Created lazily when a
  finding arrives (engine ingest or Hacker handoff), registered explicitly
  via GitHub OAuth (source `github`, Console connect flow), or added manually
  (source `manual`). `source` ranks github > engine > handoff > manual and is
  never downgraded. Every panel targets the shared selection from
  `useProjectSelection()` (PanelShell selector). Project detail:
  `/dashboard/projects/:repo`.
- `oauthStates` table — single-use, 10-minute CSRF states for the GitHub
  OAuth flow. The access token is stored only on the user row and is never
  returned to the client.
- `findings` table (Convex) — orchestrator.py output or Hacker handoffs.
  `attackSteps[].verdict` is the REAL recorded re-attack result.
- `workflowRuns` table — validation/re-validation runs as **executable
  work**. A queued run is picked up by the engine via `/api/runs/pending`,
  claimed via `/api/runs/claim` (the claim response carries the run's scope:
  authorized/blocked paths the engine must respect), and resolved via
  `/api/runs/resolve`. The UI must still never present a queued/claimed run
  as a completed scan. A daily cron queues per-project re-validation runs.
- `approvals` table — developer-approved buffers (source `ai` or `manual`)
  the engine applies, re-attacks, and resolves with a verdict.
- `revalidations` table — queued fresh re-attacks ("Re-run validation").

Every number shown in any panel is derived from these tables through
`usePurpleGuardData(projectId?)`. **Panels must not invent data**: no fake
agents, fake activity, fake confidence scores. Confidence on attack paths
is the derived fraction of validated steps still exploitable; agent
telemetry is explicitly shown as "not yet wired" in ECC until real
orchestration lands. Blue team and purple-team layers remain **unbuilt**
(see docs/AUDIT_AND_PLAN.md for verified status).

Engine routes (`/api/*`) require `X-Engine-Key` (see `docs/ENGINE_API.md`);
all Convex functions used by the UI verify auth server-side.

---

## Rules for future changes

1. **Do not duplicate a responsibility across panels.** If a feature fits
   the matrix above, it lives in exactly one surface; other panels link to
   it.
2. **Do not add a fifth parallel dashboard.** New capability = new section
   inside the owning surface, or a new table + owning panel.
3. **The approval boundary stays in the Developer panel.** ECC can
   orchestrate; it must never apply code without an explicit developer
   approval recorded in `approvals`.
4. **Verdicts come from the engine.** The panel replays recorded verdicts
   for seed data, queues fresh re-attacks for engine-backed findings, and
   never derives VERIFIED FIXED from a heuristic.
5. **Seed data is a fallback, not a source.** When Convex has findings, all
   panels render engine data; the seed only appears while the table is
   empty.
