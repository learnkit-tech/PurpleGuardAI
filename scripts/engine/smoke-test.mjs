#!/usr/bin/env node
/**
 * PurpleGuard engine contract smoke test (negative paths only).
 *
 * Verifies the honesty guarantees and fail-closed behavior of the live
 * deployment WITHOUT creating any state:
 *
 *   1. Engine routes reject requests without X-Engine-Key (401)
 *   2. /api/ingest_finding REJECTS payloads without attackSteps (422)
 *      — findings can never be invented (docs/ENGINE_API.md §1)
 *   3. /api/ingest_finding REJECTS payloads without id (422)
 *   4. /api/runs/claim with a bogus run id (422)
 *   5. /api/github/start still fail-closed without state (400)
 *
 * Usage:
 *   SITE=https://expert-elk-927.convex.site KEY=<ENGINE_API_KEY> \
 *     node scripts/engine/smoke-test.mjs
 *
 * Exit 0 = all checks passed. Exit 1 = a guarantee is broken.
 * No npm script needed — CI (or a human) runs it with SITE + KEY env vars.
 */

const SITE = (process.env.SITE ?? "").replace(/\/+$/, "");
const KEY = process.env.KEY ?? "";

if (!SITE || !KEY) {
  console.error(
    "Usage: SITE=https://<deployment>.convex.site KEY=<ENGINE_API_KEY> node scripts/engine/smoke-test.mjs",
  );
  process.exit(1);
}

let failures = 0;

function check(name, cond, detail = "") {
  const status = cond ? "PASS" : "FAIL";
  console.log(`  [${status}] ${name}${detail ? ` — ${detail}` : ""}`);
  if (!cond) failures += 1;
}

async function call(path, { method = "GET", key = KEY, body } = {}) {
  const res = await fetch(`${SITE}${path}`, {
    method,
    headers: {
      ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      ...(key ? { "X-Engine-Key": key } : {}),
    },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
  // Read the body once, then try to parse it (github routes return plain text).
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    /* plain-text response */
  }
  return { status: res.status, json, text: json ? null : text };
}

async function main() {
  console.log(`smoke-testing ${SITE}\n`);

  // 1. Fail-closed auth on every engine route.
  for (const path of [
    "/api/runs/pending",
    "/api/approvals/pending",
    "/api/revalidate/pending",
  ]) {
    const r = await call(path, { key: "" });
    check(`${path} without key → 401`, r.status === 401, `got ${r.status}`);
  }
  const ingestNoKey = await call("/api/ingest_finding", {
    method: "POST",
    key: "",
    body: {},
  });
  check("/api/ingest_finding without key → 401", ingestNoKey.status === 401, `got ${ingestNoKey.status}`);

  // 2. THE honesty guarantee: no attackSteps ⇒ no finding can be invented.
  const noSteps = await call("/api/ingest_finding", {
    method: "POST",
    body: { id: "SMOKE-NO-STEPS", title: "must be rejected" },
  });
  check(
    "ingest without attackSteps → 422 (never invent verdicts)",
    noSteps.status === 422,
    `got ${noSteps.status}`,
  );

  // 3. id is required as well.
  const noId = await call("/api/ingest_finding", {
    method: "POST",
    body: { attackSteps: [{ name: "x", verdict: "blocked" }] },
  });
  check("ingest without id → 422", noId.status === 422, `got ${noId.status}`);

  // 4. Bogus run claim is rejected (no state mutation).
  const bogusClaim = await call("/api/runs/claim", {
    method: "POST",
    body: { runId: "smoke-bogus-run-id-00000000000000000" },
  });
  check("claim with bogus runId → 422", bogusClaim.status === 422, `got ${bogusClaim.status}`);

  // 5. GitHub start stays fail-closed on missing state.
  const ghStart = await call("/api/github/start");
  check("/api/github/start without state → 400", ghStart.status === 400, `got ${ghStart.status}`);

  console.log("");
  if (failures > 0) {
    console.error(`✗ ${failures} check(s) failed — a contract guarantee is broken.`);
    process.exit(1);
  }
  console.log("✓ all contract guarantees hold.");
}

main().catch((e) => {
  console.error(`smoke test crashed: ${e.message}`);
  process.exit(1);
});
