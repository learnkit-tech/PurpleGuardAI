# Engine Onboarding — live deployment `expert-elk-927`

How to wire the real PurpleGuard engine to the running Convex backend. The
transport layer is done and verified; what remains is replacing the marked
stubs in `scripts/engine/orchestrator.py` with real validation logic.

## Status

| Piece | Status |
| --- | --- |
| `ENGINE_API_KEY` set on deployment | ✅ live (401 without key, 200 with) |
| Runs contract (pending → claim → resolve) | ✅ live-verified end-to-end |
| Scope delivery on claim | ✅ verified (authorized/blocked paths returned) |
| Findings ingest (`/api/ingest_finding`) | ✅ live (rejects payloads without attackSteps) |
| Approvals / revalidations queues | ✅ live, poll + resolve routes verified |
| GitHub OAuth connect | ✅ user-verified end-to-end |
| Static validators (wired + tested) | ✅ `scripts/engine/validators.py`, 20 unit/path tests green |
| Network-probe offensive validators | ⬜ external engine repo — see "Validator seam" below |

## 1. Configure the engine environment

Create `scripts/engine/.env` (git-ignored; `.env.example` is protected by the
platform, so copy the block below into your file):

```bash
# Convex HTTP actions origin — MUST be *.convex.site, NOT *.convex.cloud
SITE=https://expert-elk-927.convex.site

# Same secret as the ENGINE_API_KEY env var on the deployment
ENGINE_API_KEY=<paste from: bun convex env get ENGINE_API_KEY>

# Optional: GitHub token (repo scope) so the engine can fetch project code.
# Private repos need this; public repos work without it.
GITHUB_TOKEN=

# Poll cadence (seconds)
POLL_INTERVAL_SECONDS=15
```

Then run:

```bash
cd scripts/engine
set -a; source .env; set +a
python3 orchestrator.py --once          # single pass
python3 orchestrator.py                 # loop
python3 orchestrator.py --once --dry-run  # wiring check only
```

The Python script speaks the exact same contract as the existing Node
reference client (`bun scripts/engine-client.mjs`), plus a GitHub repo fetch
helper for the validator to consume.

## 2. Validators (wired) and the validator seam

`scripts/engine/validators.py` now performs REAL deterministic validation
against the fetched, scope-filtered files:

- Committed cloud/VCS/messaging credential literals (AWS, GitHub, Slack)
- Committed private key blocks
- Hardcoded secret-looking assignments (env reads are not flagged)
- Disabled TLS certificate verification (Python + Node forms)

Honesty semantics (enforced by tests in `test_validators.py` and
`test_orchestrator_path.py`):

- Findings exist only for code that actually matched in an in-scope file.
- `exploitable` means the check itself deterministically demonstrated the
  exposure from the artifact — never a claimed network attack.
- The "demonstrate remote use" step is recorded as `blocked` with an explicit
  log: static checks do not attempt live provider authentication.
- Evidence, `vulnerableMarker`, and step logs are REDACTED.
  `vulnerableCode` stays raw by design — it seeds the Developer workspace
  buffer that an approval applies back to the repo.
- Scope is applied first (fail closed: no scope ⇒ no inspection), and
  vendored/generated trees (`vendor/`, `node_modules/`, `dist/`, `build/`,
  `.git/`) are skipped as not the developer's remediation surface.
- A dry run never fetches and never validates; it resolves `ok:false`.

**Validator seam:** network-probe offensive validators (live credential
reuse probes, endpoint attacks, per-step `reverification.py` execution)
belong in the external engine repo. Their write-backs use the same
approvals/revalidations resolve routes documented above — the gate, the
honesty rules, and the data model are already in place for them.

Run the focused suites (stdlib unittest, HTTP boundary mocked, validators
run for real):

```bash
cd scripts/engine
python3 -m unittest test_validators test_orchestrator_path -v
```

## 3. Verify the loop end-to-end

1. Queue a run from the UI (Console → project → Run validation, or the
   Hacker panel).
2. `python3 orchestrator.py --once` — you should see:
   `claimed run <id> project=<repo> kind=validation authorized=[...]`
3. Real findings appear in Hacker → Developer → Verification panels within
   seconds (Convex queries are reactive).
4. If nothing was validated, the run shows **failed** with the honest note —
   that is by design, not a bug.

## 4. Contract smoke test (CI-ready)

`scripts/engine/smoke-test.mjs` verifies the honesty guarantees and
fail-closed behavior against any deployment **without creating state**:

```bash
SITE=https://expert-elk-927.convex.site KEY=<ENGINE_API_KEY> \
  node scripts/engine/smoke-test.mjs
```

Checks: 401 without `X-Engine-Key` on every engine route; 422 on ingesting
findings without `attackSteps` or `id` (verdicts can never be invented);
422 on bogus run claims; 400 on `github/start` without state. Exit 0 = all
guarantees hold. Run it in CI after every engine/backend change.

## 5. Non-goals

- The engine never receives Convex auth credentials — `X-Engine-Key` only.
- The engine never sees user OAuth tokens; it uses its own `GITHUB_TOKEN`
  (or per-user tokens remain a server-side concern on the deployment).
- Browsers cannot call `/api/*` engine routes: CORS is restricted to the app
  origin and browsers never hold the engine key.
