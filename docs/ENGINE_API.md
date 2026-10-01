# PurpleGuard Engine API

HTTP bridge between the PurpleGuard Python engine (`orchestrator.py`) and the
Developer Panel web app (Convex). The engine writes findings, polls work, and
posts re-attack verdicts back; the panel renders what the engine produced.

**Base URL:** your Convex deployment's **HTTP actions** host —
`https://<deployment>.convex.site` (e.g. `https://expert-elk-927.convex.site`).
Note this is `.convex.site`, NOT `.convex.cloud` — the `.cloud` host is for
queries/mutations and returns 404 for these routes.

---

## Authentication

Every `/api/*` engine route requires the header:

```
X-Engine-Key: <ENGINE_API_KEY>
```

`ENGINE_API_KEY` is a Convex environment variable set in the Convex dashboard
for this deployment. If it is unset, **all** engine requests fail with 401 —
the bridge fails closed.

Requests without the header, or with a wrong value, get:

```json
{ "error": "missing or invalid X-Engine-Key header" }
```

**CORS:** browsers can only call these routes from the app origin
(`APP_ORIGIN` env var, falling back to `CONVEX_SITE_URL`). The Python engine
does not need CORS — it authenticates with `X-Engine-Key`. Requests from any
other origin receive no CORS headers, and preflights are not answered.

---

## 1. POST /api/ingest_finding

The engine pushes one finding per run after the final re-attack verdict.

### Request

Headers: `Content-Type: application/json`, `X-Engine-Key: …`

```json
{
  "id": "F-2841",
  "title": "Exposed AWS secret in auth-service/.env",
  "severity": "critical",
  "vulnerabilityType": "Hardcoded credential / secret leakage",
  "repo": "auth-service",
  "file": "src/config/auth.ts",
  "location": "lines 3–8",
  "attackSurface": "Repository · CI environment",
  "attackPath": [
    "Commit history scan finds a long-lived AWS access key",
    "Validator confirms the key is active"
  ],
  "explanation": "A static AWS access key is hardcoded in the config module…",
  "remediation": "Load credentials from the environment and rotate the key…",
  "vulnerableCode": "export const AWS_ACCESS_KEY_ID = \"AKIA…\";",
  "proposedPatch": "export const AWS_ACCESS_KEY_ID = process.env.AWS_ACCESS_KEY_ID;",
  "fixedCode": "export const AWS_ACCESS_KEY_ID = process.env.AWS_ACCESS_KEY_ID;",
  "reTestChecks": [
    "No credential literal present in source"
  ],
  "vulnerableMarker": "AKIAIOSFODNN7EXAMPLE",
  "evidence": [
    {
      "id": "ev-1",
      "kind": "code",
      "label": "Key literal in source",
      "content": "src/config/auth.ts:4  export const AWS_ACCESS_KEY_ID = \"AKIA…\";"
    }
  ],
  "attackSteps": [
    {
      "name": "Probe with committed key",
      "description": "Authenticate with the committed key and list buckets",
      "criteria": "ListBuckets succeeds with any credential found in the repo",
      "verdict": "exploitable",
      "log": [
        "[validator] ListBuckets payments-prod: allowed"
      ]
    }
  ],
  "testerNote": "Authorized validation only: read-only ListBuckets.",
  "run": {
    "run_id": "run-2026-09-24-001",
    "started_at": "2026-09-24T10:12:33Z",
    "finished_at": "2026-09-24T10:14:02Z"
  }
}
```

**Required fields:** `id`, `attackSteps` (non-empty). A payload without
`attackSteps` is rejected — per-step verdicts must come from
`reverification.py`, never be invented. Unknown fields are ignored; missing
optionals get sensible fallbacks in the panel.

`attackSteps[].verdict` must be `"blocked"` or `"exploitable"` (anything else
reads as `"exploitable"`).

### Response

```json
{ "findingId": "F-2841", "updated": false }
```

`updated: true` means the finding already existed and was overwritten with
this run's payload.

### Errors

| Status | Meaning |
| --- | --- |
| 400 | Invalid JSON body |
| 401 | Missing/invalid `X-Engine-Key` (or key not configured) |
| 422 | Validation error: missing `id` or empty `attackSteps` |

### curl

```bash
curl -X POST "https://<your-deployment>.convex.site/api/ingest_finding" \
  -H "Content-Type: application/json" \
  -H "X-Engine-Key: $ENGINE_API_KEY" \
  --data @finding.json
```

---

## 2. GET /api/approvals/pending

The engine polls this to pick up approvals from the panel (ECC patches and
manual saves). Each approval carries the **full workspace buffer** the
developer approved — the engine applies it, re-attacks, and resolves it.

### Request

Headers: `X-Engine-Key: …`

### Response

```json
{
  "approvals": [
    {
      "_id": "j57abcd1234",
      "findingId": "F-2841",
      "source": "ai",
      "code": "export const AWS_ACCESS_KEY_ID = process.env.AWS_ACCESS_KEY_ID;\n…",
      "status": "pending",
      "requestedAt": 1769320800000
    }
  ]
}
```

`source` is `"ai"` (ECC patch approved by the developer) or `"manual"`
(developer's own buffer saved through the approval gate).

### Errors

| Status | Meaning |
| --- | --- |
| 401 | Missing/invalid `X-Engine-Key` |

### curl

```bash
curl "https://<your-deployment>.convex.site/api/approvals/pending" \
  -H "X-Engine-Key: $ENGINE_API_KEY"
```

---

## 3. POST /api/approvals/resolve

The engine posts the result of applying an approved buffer and re-attacking.

### Request

Headers: `Content-Type: application/json`, `X-Engine-Key: …`

```json
{
  "approvalId": "j57abcd1234",
  "verdict": "VERIFIED_FIXED",
  "attackSteps": [
    { "name": "Probe with committed key", "verdict": "blocked" }
  ],
  "engineRunId": "run-2026-09-24-002",
  "log": [
    "[engine] applied approved buffer to src/config/auth.ts",
    "[engine] re-attacked: ListBuckets with committed key → denied"
  ]
}
```

- `verdict`: `"VERIFIED_FIXED"` or `"STILL_VULNERABLE"`.
- `attackSteps[].name` must match the finding's step names; those steps get
  their `verdict` updated in the finding payload. Unmatched names are
  ignored.
- `engineRunId` and `log` are optional.

### Response

```json
{ "ok": true, "findingUpdated": true }
```

Resolving an already-applied approval returns
`{ "ok": true, "alreadyApplied": true }`.

### Errors

| Status | Meaning |
| --- | --- |
| 400 | Missing `approvalId`, `verdict`, or `attackSteps` |
| 401 | Missing/invalid `X-Engine-Key` |
| 422 | Approval id not found |

### curl

```bash
curl -X POST "https://<your-deployment>.convex.site/api/approvals/resolve" \
  -H "Content-Type: application/json" \
  -H "X-Engine-Key: $ENGINE_API_KEY" \
  -d '{
    "approvalId": "j57abcd1234",
    "verdict": "VERIFIED_FIXED",
    "attackSteps": [{"name": "Probe with committed key", "verdict": "blocked"}],
    "log": ["[engine] applied buffer, re-attacked → blocked"]
  }'
```

---

## 4. GET /api/revalidate/pending

The panel queues a fresh re-attack when the developer presses
"Re-run validation" on an engine-backed finding. The engine polls this route.

### Request

Headers: `X-Engine-Key: …`

### Response

```json
{
  "revalidations": [
    {
      "_id": "j57wxyz5678",
      "findingId": "F-2839",
      "status": "pending",
      "requestedAt": 1769320900000
    }
  ]
}
```

### Errors

| Status | Meaning |
| --- | --- |
| 401 | Missing/invalid `X-Engine-Key` |

### curl

```bash
curl "https://<your-deployment>.convex.site/api/revalidate/pending" \
  -H "X-Engine-Key: $ENGINE_API_KEY"
```

---

## 5. POST /api/revalidate/resolve

The engine posts the result of a queued fresh re-attack.

### Request

Headers: `Content-Type: application/json`, `X-Engine-Key: …`

```json
{
  "revalidationId": "j57wxyz5678",
  "verdict": "STILL_VULNERABLE",
  "attackSteps": [
    { "name": "Boolean-blind injection probe", "verdict": "exploitable" }
  ],
  "engineRunId": "run-2026-09-24-003",
  "log": [
    "[engine] re-attacked /api/v2/orders?q=' OR '1'='1 → 200 with rows"
  ]
}
```

Same semantics as `/api/approvals/resolve`: `attackSteps` names are matched
against the finding and merged, so the panel shows the latest run.

### Response

```json
{ "ok": true, "findingUpdated": true }
```

Resolving an already-resolved revalidation returns
`{ "ok": true, "alreadyResolved": true }`.

### Errors

| Status | Meaning |
| --- | --- |
| 400 | Missing `revalidationId`, `verdict`, or `attackSteps` |
| 401 | Missing/invalid `X-Engine-Key` |
| 422 | Revalidation id not found |

### curl

```bash
curl -X POST "https://<your-deployment>.convex.site/api/revalidate/resolve" \
  -H "Content-Type: application/json" \
  -H "X-Engine-Key: $ENGINE_API_KEY" \
  -d '{
    "revalidationId": "j57wxyz5678",
    "verdict": "STILL_VULNERABLE",
    "attackSteps": [{"name": "Boolean-blind injection probe", "verdict": "exploitable"}],
    "log": ["[engine] re-attack succeeded — vulnerability reproduced"]
  }'
```

---

## 6. GET /api/runs/pending

The engine polls this to discover **queued validation / re-validation runs**.
A queued run is executable work: claim it, respect the returned scope, ingest
findings via `POST /api/ingest_finding`, then resolve the run.

### Request

Headers: `X-Engine-Key: …`

### Response

```json
{
  "runs": [
    {
      "_id": "j57run0001",
      "projectId": "purpleguard-api",
      "kind": "validation",
      "createdAt": 1769320000000
    }
  ]
}
```

### Errors

| Status | Meaning |
| --- | --- |
| 401 | Missing/invalid `X-Engine-Key` |

### curl

```bash
curl "https://<your-deployment>.convex.site/api/runs/pending" \
  -H "X-Engine-Key: $ENGINE_API_KEY"
```

---

## 7. POST /api/runs/claim

Atomically claim one queued run. The response carries the run's **scope** —
the authorization artifacts the engine MUST respect. Claiming moves the run
to `running`; if another worker already claimed it, `ok: false` comes back.

### Request

Headers: `Content-Type: application/json`, `X-Engine-Key: …`

```json
{
  "runId": "j57run0001",
  "engineRunId": "run-2026-09-24-101"
}
```

`engineRunId` is optional and is stamped on the run for traceability.

### Response

```json
{
  "ok": true,
  "projectId": "purpleguard-api",
  "kind": "validation",
  "scope": {
    "authorizedPaths": ["/**"],
    "blockedPaths": []
  }
}
```

Claiming an already-claimed run returns `{ "ok": false, "reason": "…" }`.

### Errors

| Status | Meaning |
| --- | --- |
| 400 | Missing `runId` |
| 401 | Missing/invalid `X-Engine-Key` |
| 422 | Run id not found |

### curl

```bash
curl -X POST "https://<your-deployment>.convex.site/api/runs/claim" \
  -H "Content-Type: application/json" \
  -H "X-Engine-Key: $ENGINE_API_KEY" \
  -d '{"runId": "j57run0001", "engineRunId": "run-2026-09-24-101"}'
```

---

## 8. POST /api/runs/resolve

Post the outcome of a claimed run. Findings themselves are pushed with
`POST /api/ingest_finding` (unchanged); `findingsIngested` is just the count
the run records for display.

### Request

Headers: `Content-Type: application/json`, `X-Engine-Key: …`

```json
{
  "runId": "j57run0001",
  "ok": true,
  "note": "3 findings pushed",
  "findingsIngested": 3,
  "engineRunId": "run-2026-09-24-101"
}
```

- `ok`: `true` if the run executed to completion (findings or none), `false`
  if it failed.
- `findingsIngested`: number of findings the engine pushed for this run via
  `/api/ingest_finding`. Optional; shown on the run in the panel.

### Response

```json
{ "ok": true }
```

### Errors

| Status | Meaning |
| --- | --- |
| 400 | Missing `runId` (string) or `ok` (boolean) |
| 401 | Missing/invalid `X-Engine-Key` |
| 422 | Run id not found |

### curl

```bash
curl -X POST "https://<your-deployment>.convex.site/api/runs/resolve" \
  -H "Content-Type: application/json" \
  -H "X-Engine-Key: $ENGINE_API_KEY" \
  -d '{"runId": "j57run0001", "ok": true, "findingsIngested": 3}'
```

---

## Loop summary

```
orchestrator.py ──GET /api/runs/pending──▶ queued workflow runs
      │
      ├─ POST /api/runs/claim ──▶ run → running; response carries SCOPE (authorized/blocked paths)
      ├─ POST /api/ingest_finding ──▶ findings table (per-finding payloads)
      └─ POST /api/runs/resolve ──▶ run completed/failed + findingsIngested count

      ├─ GET /api/approvals/pending ◀── panel approvals (ai | manual)
      └─ POST /api/approvals/resolve ──▶ verdict + merged attackSteps
      │
      ├─ GET /api/revalidate/pending ◀── panel "Re-run validation"
      └─ POST /api/revalidate/resolve ──▶ fresh verdict + merged attackSteps
```

Scheduled re-validation: a daily Convex cron queues a re-validation run per
project (de-duped against active runs); the engine picks it up through the
same runs flow.

The panel never invents a verdict for engine-backed findings: it either
replays the recorded attackSteps (imported data) or waits for the engine to
post a fresh one. All engine routes require `X-Engine-Key`; all panel routes
require a Convex auth session checked server-side.

---

## Appendix A — Reference engine client

`scripts/engine-client.mjs` is a minimal, honest reference implementation of
this contract. It demonstrates the runs loop (poll → claim → observe scope →
resolve) and surfaces pending approvals/revalidations without resolving them.
It does **not** scan or fabricate findings — a dry run resolves `ok:false`.

```bash
SITE=https://<deployment>.convex.site KEY=<ENGINE_API_KEY> \
  bun scripts/engine-client.mjs --once --dry-run
```

`--dry-run` verifies wiring end-to-end (auth, claim, scope delivery, resolve)
without performing any validation. `--once` does a single poll pass and exits;
without flags it loops every 15 s. The real Python engine should replace the
marked `// 3.` section with actual validator execution.

---

## Appendix B — GitHub OAuth connect flow (Phase 2)

The panel's "Connect your project → GitHub" path uses first-party OAuth.
The browser leaves the app, so identity is bound server-side **before** the
redirect:

1. Panel calls the authenticated Convex mutation `github.beginConnection`
   with `{ origin: window.location.origin }`. It stores a single-use state
   row in `oauthStates` bound to the signed-in user id **and** the app origin,
   with a 10-minute TTL.
2. Panel redirects the browser to
   `GET https://<deployment>.convex.site/api/github/start?state=<state>`.
   Missing state → 400. Unset `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET`
   → 503 with an explicit message (fail closed).
3. `/api/github/start` 302s to GitHub's authorize URL (`repo read:org`).
4. GitHub redirects to `GET /api/github/callback?code=…&state=…`.
5. `/api/github/callback` consumes the state (single use), exchanges the
   code, validates the token against `api.github.com/user`, stores the token
   on the **bound user** (the callback navigation carries no Convex auth
   session — identity comes from the state row), then 302s back to the
   stored app origin at `/dashboard?github=connected`.
6. On any failure the callback returns a plain-text 400 naming the reason;
   the panel's manual identifier entry (`projects.addManual`) keeps the
   connect flow usable without OAuth.

Fail-closed behavior: without the GitHub OAuth env vars set on the
deployment, step 2 answers 503 and no state is ever exchanged.
