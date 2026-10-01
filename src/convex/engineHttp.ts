import { httpAction } from "./_generated/server";
import { internal } from "./_generated/api";

/* ------------------------------------------------------------------ */
/* Auth: X-Engine-Key                                                  */
/* ------------------------------------------------------------------ */

/**
 * All /api/* engine routes require `X-Engine-Key: <ENGINE_API_KEY>`.
 * The key lives in the Convex dashboard env vars and matches the secret
 * configured in orchestrator.py. Fail closed: if the env var is not set,
 * every engine request is rejected.
 */
function requireEngineKey(request: Request): Response | null {
  const expected = process.env.ENGINE_API_KEY;
  if (!expected) {
    return json(
      { error: "ENGINE_API_KEY is not configured on this deployment" },
      401,
    );
  }
  const provided = request.headers.get("X-Engine-Key") ?? "";
  if (provided.length !== expected.length || provided !== expected) {
    return json({ error: "missing or invalid X-Engine-Key header" }, 401);
  }
  return null;
}

/* ------------------------------------------------------------------ */
/* CORS: app origin only                                               */
/* ------------------------------------------------------------------ */

/**
 * Browser clients are only ever the PurpleGuard web app, so CORS is
 * restricted to the app origin (APP_ORIGIN env var, falling back to
 * CONVEX_SITE_URL). The Python engine is a server-to-server client and
 * does not need or receive CORS headers — it also authenticates with
 * X-Engine-Key, which browsers never hold.
 */
function allowedOrigin(request: Request): string | null {
  const configured = (
    process.env.APP_ORIGIN ??
    process.env.CONVEX_SITE_URL ??
    ""
  ).replace(/\/$/, "");
  const origin = request.headers.get("Origin");
  if (!configured || !origin) return null;
  return origin.replace(/\/$/, "") === configured ? origin : null;
}

function json(body: unknown, status: number, request?: Request) {
  const origin = request ? allowedOrigin(request) : null;
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...(origin
        ? {
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Credentials": "true",
          }
        : {}),
    },
  });
}

function preflightResponse(request: Request) {
  const origin = allowedOrigin(request);
  return new Response(null, {
    status: 204,
    headers: origin
      ? {
          "Access-Control-Allow-Origin": origin,
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, X-Engine-Key",
          "Access-Control-Max-Age": "86400",
        }
      : {},
  });
}

export const respondPreflight = httpAction(async (ctx, request) =>
  preflightResponse(request),
);

/* ------------------------------------------------------------------ */
/* POST /api/ingest_finding                                            */
/* ------------------------------------------------------------------ */

export const ingestFinding = httpAction(async (ctx, request) => {
  if (request.method === "OPTIONS") return preflightResponse(request);
  const unauthorized = requireEngineKey(request);
  if (unauthorized) return unauthorized;

  let payload: unknown;
  try {
    payload = await request.json();
  } catch {
    return json({ error: "invalid JSON body" }, 400, request);
  }
  try {
    const result = await ctx.runMutation(internal.findings.ingestFromEngine, {
      payload,
    });
    return json(result, 200, request);
  } catch (e) {
    return json(
      { error: e instanceof Error ? e.message : "ingest failed" },
      422,
      request,
    );
  }
});

/* ------------------------------------------------------------------ */
/* GET /api/runs/pending                                               */
/* ------------------------------------------------------------------ */

/**
 * The engine polls this to discover queued validation / re-validation runs.
 * A queued run is executable work: claim it via /api/runs/claim, respect the
 * returned scope, ingest findings via /api/ingest_finding, then post the
 * outcome via /api/runs/resolve.
 */
export const pendingRuns = httpAction(async (ctx, request) => {
  if (request.method === "OPTIONS") return preflightResponse(request);
  const unauthorized = requireEngineKey(request);
  if (unauthorized) return unauthorized;

  const docs = await ctx.runQuery(internal.workflow.pendingForEngine, {});
  return json(
    {
      runs: docs.map((r) => ({
        _id: r._id,
        projectId: r.projectId,
        kind: r.kind,
        createdAt: r.createdAt,
      })),
    },
    200,
    request,
  );
});

/* ------------------------------------------------------------------ */
/* POST /api/runs/claim                                                */
/* ------------------------------------------------------------------ */

/**
 * Atomically claim one queued run. The response carries the run's SCOPE —
 * the authorization artifacts the engine must respect (authorized paths,
 * blocked paths). Claiming moves the run to "running"; if it is already
 * claimed, the response says so.
 */
export const claimRun = httpAction(async (ctx, request) => {
  if (request.method === "OPTIONS") return preflightResponse(request);
  const unauthorized = requireEngineKey(request);
  if (unauthorized) return unauthorized;

  let body: Record<string, unknown>;
  try {
    body = (await request.json()) as Record<string, unknown>;
  } catch {
    return json({ error: "invalid JSON body" }, 400, request);
  }
  const runId = body.runId;
  if (typeof runId !== "string") {
    return json({ error: "runId is required" }, 400, request);
  }
  try {
    const result = await ctx.runMutation(internal.workflow.claimForEngine, {
      runId: runId as never,
      engineRunId:
        typeof body.engineRunId === "string" ? body.engineRunId : undefined,
    });
    return json(result, 200, request);
  } catch (e) {
    return json(
      { error: e instanceof Error ? e.message : "claim failed" },
      422,
      request,
    );
  }
});

/* ------------------------------------------------------------------ */
/* POST /api/runs/resolve                                              */
/* ------------------------------------------------------------------ */

/**
 * Post the outcome of a claimed run. The engine reports whether it ran OK,
 * an optional note, and `findingsIngested` — the number of findings it
 * pushed via /api/ingest_finding for this run. The panel displays that
 * count on the run; it is never derived here.
 */
export const resolveRun = httpAction(async (ctx, request) => {
  if (request.method === "OPTIONS") return preflightResponse(request);
  const unauthorized = requireEngineKey(request);
  if (unauthorized) return unauthorized;

  let body: Record<string, unknown>;
  try {
    body = (await request.json()) as Record<string, unknown>;
  } catch {
    return json({ error: "invalid JSON body" }, 400, request);
  }
  const runId = body.runId;
  const ok = body.ok;
  if (typeof runId !== "string" || typeof ok !== "boolean") {
    return json({ error: "runId (string) and ok (boolean) are required" }, 400, request);
  }
  try {
    const result = await ctx.runMutation(internal.workflow.resolveRun, {
      runId: runId as never,
      ok,
      note: typeof body.note === "string" ? body.note : undefined,
      findingsIngested:
        typeof body.findingsIngested === "number" ? body.findingsIngested : undefined,
      engineRunId:
        typeof body.engineRunId === "string" ? body.engineRunId : undefined,
    });
    return json(result, 200, request);
  } catch (e) {
    return json(
      { error: e instanceof Error ? e.message : "resolve failed" },
      422,
      request,
    );
  }
});

/* ------------------------------------------------------------------ */
/* GET /api/approvals/pending                                          */
/* ------------------------------------------------------------------ */

export const pendingApprovals = httpAction(async (ctx, request) => {
  if (request.method === "OPTIONS") return preflightResponse(request);
  const unauthorized = requireEngineKey(request);
  if (unauthorized) return unauthorized;

  const docs = await ctx.runQuery(internal.approvals.pendingForEngine, {});
  return json({ approvals: docs }, 200, request);
});

/* ------------------------------------------------------------------ */
/* POST /api/approvals/resolve                                         */
/* ------------------------------------------------------------------ */

export const resolveApproval = httpAction(async (ctx, request) => {
  if (request.method === "OPTIONS") return preflightResponse(request);
  const unauthorized = requireEngineKey(request);
  if (unauthorized) return unauthorized;

  let body: Record<string, unknown>;
  try {
    body = (await request.json()) as Record<string, unknown>;
  } catch {
    return json({ error: "invalid JSON body" }, 400, request);
  }
  const approvalId = body.approvalId;
  const verdict = body.verdict;
  const steps = body.attackSteps;
  if (
    typeof approvalId !== "string" ||
    typeof verdict !== "string" ||
    !Array.isArray(steps)
  ) {
    return json(
      { error: "approvalId, verdict, attackSteps are required" },
      400,
      request,
    );
  }
  try {
    const result = await ctx.runMutation(internal.approvals.resolveApproval, {
      approvalId: approvalId as never,
      verdict,
      attackSteps: steps as Array<{ name: string; verdict: string }>,
      engineRunId:
        typeof body.engineRunId === "string" ? body.engineRunId : undefined,
      log: Array.isArray(body.log)
        ? (body.log as string[]).filter((l) => typeof l === "string")
        : undefined,
    });
    return json(result, 200, request);
  } catch (e) {
    return json(
      { error: e instanceof Error ? e.message : "resolve failed" },
      422,
      request,
    );
  }
});

/* ------------------------------------------------------------------ */
/* GET /api/revalidate/pending                                         */
/* ------------------------------------------------------------------ */

export const pendingRevalidations = httpAction(async (ctx, request) => {
  if (request.method === "OPTIONS") return preflightResponse(request);
  const unauthorized = requireEngineKey(request);
  if (unauthorized) return unauthorized;

  const docs = await ctx.runQuery(internal.revalidations.pendingForEngine, {});
  return json({ revalidations: docs }, 200, request);
});

/* ------------------------------------------------------------------ */
/* POST /api/revalidate/resolve                                        */
/* ------------------------------------------------------------------ */

export const resolveRevalidation = httpAction(async (ctx, request) => {
  if (request.method === "OPTIONS") return preflightResponse(request);
  const unauthorized = requireEngineKey(request);
  if (unauthorized) return unauthorized;

  let body: Record<string, unknown>;
  try {
    body = (await request.json()) as Record<string, unknown>;
  } catch {
    return json({ error: "invalid JSON body" }, 400, request);
  }
  const revalidationId = body.revalidationId;
  const verdict = body.verdict;
  const steps = body.attackSteps;
  if (
    typeof revalidationId !== "string" ||
    typeof verdict !== "string" ||
    !Array.isArray(steps)
  ) {
    return json(
      { error: "revalidationId, verdict, attackSteps are required" },
      400,
      request,
    );
  }
  try {
    const result = await ctx.runMutation(
      internal.revalidations.resolveRevalidation,
      {
        revalidationId: revalidationId as never,
        verdict,
        attackSteps: steps as Array<{ name: string; verdict: string }>,
        engineRunId:
          typeof body.engineRunId === "string" ? body.engineRunId : undefined,
        log: Array.isArray(body.log)
          ? (body.log as string[]).filter((l) => typeof l === "string")
          : undefined,
      },
    );
    return json(result, 200, request);
  } catch (e) {
    return json(
      { error: e instanceof Error ? e.message : "resolve failed" },
      422,
      request,
    );
  }
});
