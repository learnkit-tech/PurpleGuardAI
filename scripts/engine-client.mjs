#!/usr/bin/env node
/**
 * PurpleGuard engine reference client (Phase 3 contract, docs/ENGINE_API.md §6–8).
 *
 * This is a MINIMAL, honest reference implementation of the engine side of the
 * runs loop — not a scanner. It demonstrates the exact HTTP contract the real
 * Python engine (orchestrator.py) must speak:
 *
 *   GET  /api/runs/pending            → list queued runs (oldest first)
 *   POST /api/runs/claim              → atomically claim one run; response
 *                                       carries its SCOPE (authorized/blocked
 *                                       paths) that the engine MUST respect
 *   POST /api/ingest_finding          → push one finding per real result
 *   POST /api/runs/resolve            → post the run outcome + finding count
 *   GET  /api/approvals/pending       → list pending fix approvals
 *   POST /api/approvals/resolve       → apply + re-attack verdict write-back
 *   GET  /api/revalidate/pending      → list queued re-attacks
 *   POST /api/revalidate/resolve      → fresh verdict write-back
 *
 * Usage:
 *   SITE=https://expert-elk-927.convex.site KEY=<ENGINE_API_KEY> \
 *     bun scripts/engine-client.mjs [--once] [--dry-run]
 *
 *   SITE  Convex deployment site origin (*.convex.site — NOT .convex.cloud)
 *   KEY   value of the ENGINE_API_KEY env var set on the deployment
 *
 * --once     poll one pass and exit (default: loop every 15s)
 * --dry-run  claim a run, print its scope, resolve it as ok:false with a
 *            note, and never ingest findings — for wiring verification only
 *
 * Honesty rules (mirrored from the platform):
 *   - Findings are ONLY ever produced by real validator runs, never invented.
 *   - A dry run resolves ok:false and says so; it never fabricates a pass.
 *   - Approval/revalidation resolution requires real apply + re-attack work;
 *     this client polls and prints them but does NOT resolve them — a real
 *     engine must.
 */

const SITE = (process.env.SITE ?? "").replace(/\/+$/, "");
const KEY = process.env.KEY ?? "";

if (!SITE || !KEY) {
  console.error(
    "Usage: SITE=https://<deployment>.convex.site KEY=<ENGINE_API_KEY> bun scripts/engine-client.mjs [--once] [--dry-run]",
  );
  process.exit(1);
}

const once = process.argv.includes("--once");
const dryRun = process.argv.includes("--dry-run");
const POLL_INTERVAL_MS = 15_000;

async function api(path, init = {}) {
  const res = await fetch(`${SITE}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      "X-Engine-Key": KEY,
      ...(init.headers ?? {}),
    },
  });
  const text = await res.text();
  let body = text;
  try {
    body = JSON.parse(text);
  } catch {
    /* non-JSON error page — keep as text */
  }
  if (!res.ok) {
    throw new Error(`${init.method ?? "GET"} ${path} → ${res.status}: ${text.slice(0, 300)}`);
  }
  return body;
}

function log(msg) {
  console.log(`[engine-client ${new Date().toISOString()}] ${msg}`);
}

/** One poll pass: drain queued runs; report (not resolve) approvals/revalidations. */
async function pollPass() {
  // 1. Queued runs.
  let runs = [];
  try {
    const data = await api("/api/runs/pending");
    runs = data.runs ?? [];
  } catch (e) {
    log(`runs/pending failed: ${e.message}`);
    return false;
  }
  if (runs.length === 0) {
    log("no queued runs");
  }

  for (const run of runs) {
    // 2. Claim — the response carries the scope the engine must respect.
    let claim;
    try {
      claim = await api("/api/runs/claim", {
        method: "POST",
        body: JSON.stringify({
          runId: run._id,
          engineRunId: `ref-${Date.now()}`,
        }),
      });
    } catch (e) {
      log(`claim ${run._id} failed: ${e.message}`);
      continue;
    }
    if (!claim.ok) {
      log(`run ${run._id} not claimable: ${claim.reason}`);
      continue;
    }

    const scope = claim.scope ?? { authorizedPaths: [], blockedPaths: [] };
    log(
      `claimed run ${run._id} project=${claim.projectId} kind=${claim.kind} ` +
        `authorized=${JSON.stringify(scope.authorizedPaths)} blocked=${JSON.stringify(scope.blockedPaths ?? [])}`,
    );

    if (dryRun) {
      // Honest dry run: never fabricate results, report the wiring check.
      await api("/api/runs/resolve", {
        method: "POST",
        body: JSON.stringify({
          runId: run._id,
          ok: false,
          note: "reference-client dry run — wiring verified, no validation executed (see docs/ENGINE_API.md §6–8)",
          findingsIngested: 0,
        }),
      });
      log(`resolved run ${run._id} as ok:false (dry run — nothing was validated)`);
      continue;
    }

    // 3. A REAL engine executes the authorized validation here, honoring the
    //    claimed scope, and pushes each finding:
    //
    //      await api("/api/ingest_finding", {
    //        method: "POST",
    //        body: JSON.stringify(findingPayload),   // requires id + attackSteps
    //      });
    //
    //    …then resolves the run with the real count:
    log(
      `run ${run._id} needs real validation work — this reference client does not scan. ` +
        `Implement orchestrator.py against docs/ENGINE_API.md §6–8, then resolve the run ` +
        `via POST /api/runs/resolve with ok + findingsIngested.`,
    );
  }

  // 4. Surface the other engine queues (a real engine would drain these too).
  try {
    const approvals = (await api("/api/approvals/pending")).approvals ?? [];
    for (const a of approvals) {
      log(
        `PENDING approval ${a._id} finding=${a.findingId} source=${a.source} — ` +
          `apply the approved buffer, re-attack, then POST /api/approvals/resolve`,
      );
    }
  } catch (e) {
    log(`approvals/pending failed: ${e.message}`);
  }
  try {
    const revals = (await api("/api/revalidate/pending")).revalidations ?? [];
    for (const r of revals) {
      log(
        `PENDING revalidation ${r._id} finding=${r.findingId} — re-attack, then POST /api/revalidate/resolve`,
      );
    }
  } catch (e) {
    log(`revalidate/pending failed: ${e.message}`);
  }

  return runs.length > 0;
}

// Main loop.
log(`starting against ${SITE}${dryRun ? " (dry-run mode)" : ""}`);
let hadWork = true;
while (!once || hadWork) {
  try {
    hadWork = await pollPass();
  } catch (e) {
    log(`poll pass error: ${e.message}`);
    hadWork = false;
  }
  if (once) break;
  await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
}
log("done");
