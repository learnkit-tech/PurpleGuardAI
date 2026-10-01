import { v } from "convex/values";
import {
  internalMutation,
  internalQuery,
  mutation,
  query,
} from "./_generated/server";
import { getCurrentUser } from "./users";
import { internal } from "./_generated/api";

/**
 * Workflow runs: the security loop as executable work (validation,
 * re-validation). Since Phase 3, a queued run is REAL work: the engine polls
 * /api/runs/pending, claims it (receiving the run's scope), executes the
 * authorized validation, ingests findings via /api/ingest_finding, and posts
 * the outcome via /api/runs/resolve. The UI must still never present a
 * queued/claimed run as a completed scan.
 */



/** Signed-in users only: start a validation/re-validation run for a project. */
export const startRun = mutation({
  args: {
    projectId: v.string(), // matches projects.repo
    kind: v.string(), // "validation" | "revalidation"
    note: v.optional(v.string()),
    /** Authorization artifacts limiting what the engine may test. */
    scope: v.optional(
      v.object({
        authorizedPaths: v.array(v.string()),
        blockedPaths: v.optional(v.array(v.string())),
      }),
    ),
  },
  handler: async (ctx, args) => {
    const user = await getCurrentUser(ctx);
    if (user === null) throw new Error("Not authenticated");
    const now = Date.now();
    const id = await ctx.db.insert("workflowRuns", {
      projectId: args.projectId,
      kind: args.kind,
      status: "queued",
      scope: args.scope,
      requestedBy: user._id,
      note: args.note,
      createdAt: now,
      updatedAt: now,
    });
    // Keep the project's activity timestamp fresh.
    await ctx.runMutation(internal.projects.touchInternal, { repo: args.projectId });
    return { runId: id };
  },
});

/** Signed-in users only: runs for one project, newest first. */
export const listForProject = query({
  args: { projectId: v.string(), limit: v.optional(v.number()) },
  handler: async (ctx, args) => {
    const user = await getCurrentUser(ctx);
    if (user === null) return [];
    const docs = await ctx.db
      .query("workflowRuns")
      .withIndex("projectId", (q) => q.eq("projectId", args.projectId))
      .collect();
    const sorted = docs.sort((a, b) => b.createdAt - a.createdAt);
    return typeof args.limit === "number"
      ? sorted.slice(0, args.limit)
      : sorted;
  },
});

/** Signed-in users only: all runs, newest first (activity feeds). */
export const listRecent = query({
  args: { limit: v.optional(v.number()) },
  handler: async (ctx, args) => {
    const user = await getCurrentUser(ctx);
    if (user === null) return [];
    const docs = await ctx.db.query("workflowRuns").collect();
    const sorted = docs.sort((a, b) => b.createdAt - a.createdAt);
    return typeof args.limit === "number"
      ? sorted.slice(0, args.limit)
      : sorted;
  },
});

/**
 * INTERNAL: reached only via /api/runs/pending (X-Engine-Key). Queued runs
 * in creation order — oldest first, so the engine works a fair queue.
 */
export const pendingForEngine = internalQuery({
  args: {},
  handler: async (ctx) => {
    const docs = await ctx.db
      .query("workflowRuns")
      .withIndex("status", (q) => q.eq("status", "queued"))
      .collect();
    return docs.sort((a, b) => a.createdAt - b.createdAt);
  },
});

/**
 * INTERNAL: reached only via /api/runs/claim (X-Engine-Key). Atomically moves
 * one queued run to "claimed" and hands back its project, kind, and scope —
 * the authorization artifacts the engine MUST respect. The claim is the
 * handoff: after this, the run is the engine's to finish or fail.
 */
export const claimForEngine = internalMutation({
  args: { runId: v.id("workflowRuns"), engineRunId: v.optional(v.string()) },
  handler: async (ctx, args) => {
    const doc = await ctx.db.get(args.runId);
    if (!doc) throw new Error("run not found");
    if (doc.status !== "queued") {
      return { ok: false as const, reason: "run is no longer queued" };
    }
    await ctx.db.patch(args.runId, {
      status: "running",
      engineRunId: args.engineRunId,
      updatedAt: Date.now(),
    });
    return {
      ok: true as const,
      projectId: doc.projectId,
      kind: doc.kind,
      scope: doc.scope ?? { authorizedPaths: ["/**"], blockedPaths: [] },
      note: doc.note,
    };
  },
});

/**
 * INTERNAL: reached only via /api/runs/resolve (X-Engine-Key). Records the
 * run outcome. `findingsIngested` is the count the engine reports of findings
 * it pushed via /api/ingest_finding for this run — the panel shows that
 * number; it is not derived here.
 */
export const resolveRun = internalMutation({
  args: {
    runId: v.id("workflowRuns"),
    ok: v.boolean(),
    note: v.optional(v.string()),
    findingsIngested: v.optional(v.number()),
    engineRunId: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const doc = await ctx.db.get(args.runId);
    if (!doc) throw new Error("run not found");
    await ctx.db.patch(args.runId, {
      status: args.ok ? "completed" : "failed",
      note: args.note,
      findingsIngested: args.findingsIngested,
      engineRunId: args.engineRunId,
      updatedAt: Date.now(),
    });
    if (doc.projectId) {
      await ctx.runMutation(internal.projects.touchInternal, { repo: doc.projectId });
    }
    return { ok: true };
  },
});
