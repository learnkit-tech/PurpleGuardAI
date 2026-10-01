import { v } from "convex/values";
import { internalMutation, internalQuery, mutation, query } from "./_generated/server";
import { getCurrentUser } from "./users";
import { internal } from "./_generated/api";

/**
 * "Re-run validation" requests for engine-backed findings.
 *
 * The panel can replay a recorded verdict, but a *fresh* re-attack must be
 * executed by the engine. Queue it here; the engine polls
 * /api/revalidate/pending, re-runs the authorized attack, and posts the
 * real verdict back via /api/revalidate/resolve — which updates the
 * finding's attackSteps so the panel reflects the latest run.
 *
 * Security model matches approvals.ts:
 * - UI functions verify the Convex auth session server-side.
 * - Engine functions are internal and reached only via /api/revalidate/*
 *   routes (X-Engine-Key).
 */

/** Signed-in users only. */
export const requestRevalidation = mutation({
  args: { findingId: v.string() },
  handler: async (tx, args) => {
    const user = await getCurrentUser(tx);
    if (user === null) throw new Error("Not authenticated");
    const id = await tx.db.insert("revalidations", {
      findingId: args.findingId,
      status: "pending",
      requestedAt: Date.now(),
    });
    return { revalidationId: id };
  },
});

/** Signed-in users only: latest revalidation for one finding (any status). */
export const latest = query({
  args: { findingId: v.string() },
  handler: async (tx, args) => {
    const user = await getCurrentUser(tx);
    if (user === null) return null;
    const docs = await tx.db
      .query("revalidations")
      .withIndex("findingId", (q) => q.eq("findingId", args.findingId))
      .collect();
    if (docs.length === 0) return null;
    return docs.reduce((a, b) => (a.requestedAt >= b.requestedAt ? a : b));
  },
});

/** Signed-in users only: recent revalidations across all findings (activity). */
export const listRecent = query({
  args: { limit: v.optional(v.number()) },
  handler: async (tx, args) => {
    const user = await getCurrentUser(tx);
    if (user === null) return [];
    const docs = await tx.db.query("revalidations").collect();
    const sorted = docs.sort((a, b) => b.requestedAt - a.requestedAt);
    return typeof args.limit === "number"
      ? sorted.slice(0, args.limit)
      : sorted;
  },
});

/**
 * INTERNAL: reached only via /api/revalidate/pending (X-Engine-Key).
 */
export const pendingForEngine = internalQuery({
  args: {},
  handler: async (tx) => {
    return await tx.db
      .query("revalidations")
      .withIndex("status", (q) => q.eq("status", "pending"))
      .collect();
  },
});

/**
 * INTERNAL: reached only via /api/revalidate/resolve (X-Engine-Key). Records
 * the real re-attack verdict and merges per-step verdicts into the finding
 * payload so the panel reflects the latest engine run.
 */
export const resolveRevalidation = internalMutation({
  args: {
    revalidationId: v.id("revalidations"),
    verdict: v.string(),
    attackSteps: v.array(v.object({ name: v.string(), verdict: v.string() })),
    engineRunId: v.optional(v.string()),
    log: v.optional(v.array(v.string())),
  },
  handler: async (tx, args) => {
    const doc = await tx.db.get(args.revalidationId);
    if (!doc) throw new Error("revalidation not found");
    if (doc.status === "resolved") return { ok: true, alreadyResolved: true };
    await tx.db.patch(args.revalidationId, {
      status: "resolved",
      verdict: args.verdict,
      attackSteps: args.attackSteps,
      engineRunId: args.engineRunId,
      log: args.log,
      resolvedAt: Date.now(),
    });

    // Merge the fresh per-step verdicts into the finding payload so the
    // panel shows the latest engine run (same behavior as approvals).
    const finding = await tx.db
      .query("findings")
      .withIndex("findingId", (q) => q.eq("findingId", doc.findingId))
      .unique();
    if (finding) {
      const payload = finding.payload as Record<string, unknown>;
      const rawSteps = Array.isArray(payload.attackSteps)
        ? (payload.attackSteps as Array<Record<string, unknown>>)
        : [];
      const merged = rawSteps.map((s) => {
        const match = args.attackSteps.find((a) => a.name === s.name);
        return match ? { ...s, verdict: match.verdict } : s;
      });
      await tx.db.patch(finding._id, {
        payload: { ...payload, attackSteps: merged },
        importedAt: Date.now(),
      });
      const repo = typeof payload.repo === "string" ? payload.repo : null;
      if (repo) {
        await tx.runMutation(internal.projects.touchInternal, { repo });
      }
    }
    return { ok: true, findingUpdated: Boolean(finding) };
  },
});
