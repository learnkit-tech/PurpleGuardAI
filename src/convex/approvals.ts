import { v } from "convex/values";
import { internalMutation, internalQuery, mutation, query } from "./_generated/server";
import { getCurrentUser } from "./users";
import { internal } from "./_generated/api";

/**
 * Approve-and-apply requests from the Developer Panel.
 *
 * Security model:
 * - `requestApproval` / `latest` are called by the signed-in web app and
 *   verify the Convex auth session server-side.
 * - `pendingForEngine` / `resolveApproval` are called by the Python engine
 *   through the /api/approvals/* routes (X-Engine-Key) and are internal so
 *   they cannot be invoked directly from the browser.
 */

/** Signed-in users only. */
export const requestApproval = mutation({
  args: {
    findingId: v.string(),
    source: v.string(),
    buffer: v.string(),
  },
  handler: async (tx, args) => {
    const user = await getCurrentUser(tx);
    if (user === null) throw new Error("Not authenticated");
    const id = await tx.db.insert("approvals", {
      findingId: args.findingId,
      source: args.source,
      code: args.buffer,
      status: "pending",
      requestedAt: Date.now(),
    });
    return { approvalId: id };
  },
});

/** Signed-in users only: latest approval for one finding (any status). */
export const latest = query({
  args: { findingId: v.string() },
  handler: async (tx, args) => {
    const user = await getCurrentUser(tx);
    if (user === null) return null;
    const docs = await tx.db
      .query("approvals")
      .withIndex("findingId", (q) => q.eq("findingId", args.findingId))
      .collect();
    if (docs.length === 0) return null;
    return docs.reduce((a, b) => (a.requestedAt >= b.requestedAt ? a : b));
  },
});

/** Signed-in users only: all approvals for one finding, oldest first. */
export const listForFinding = query({
  args: { findingId: v.string() },
  handler: async (tx, args) => {
    const user = await getCurrentUser(tx);
    if (user === null) return [];
    return await tx.db
      .query("approvals")
      .withIndex("findingId", (q) => q.eq("findingId", args.findingId))
      .collect();
  },
});

/**
 * INTERNAL: reached only via /api/approvals/pending (X-Engine-Key).
 * Returns raw approval docs the engine can iterate.
 */
export const pendingForEngine = internalQuery({
  args: {},
  handler: async (tx) => {
    return await tx.db
      .query("approvals")
      .withIndex("status", (q) => q.eq("status", "pending"))
      .collect();
  },
});

/** Signed-in users only: recent approvals across all findings (activity). */
export const listRecent = query({
  args: { limit: v.optional(v.number()) },
  handler: async (tx, args) => {
    const user = await getCurrentUser(tx);
    if (user === null) return [];
    const docs = await tx.db.query("approvals").collect();
    const sorted = docs.sort((a, b) => b.requestedAt - a.requestedAt);
    return typeof args.limit === "number"
      ? sorted.slice(0, args.limit)
      : sorted;
  },
});

/** Signed-in users only: pending approvals for the panel badge. */
export const pending = query({
  args: {},
  handler: async (tx) => {
    const user = await getCurrentUser(tx);
    if (user === null) return [];
    return await tx.db
      .query("approvals")
      .withIndex("status", (q) => q.eq("status", "pending"))
      .collect();
  },
});

/**
 * INTERNAL: reached only via /api/approvals/resolve (X-Engine-Key). Marks
 * the approval applied, records the REAL re-attack verdict, and merges the
 * per-step verdicts back into the finding payload so the panel reflects
 * the latest engine run.
 */
export const resolveApproval = internalMutation({
  args: {
    approvalId: v.id("approvals"),
    verdict: v.string(),
    attackSteps: v.array(v.object({ name: v.string(), verdict: v.string() })),
    engineRunId: v.optional(v.string()),
    log: v.optional(v.array(v.string())),
  },
  handler: async (tx, args) => {
    const doc = await tx.db.get(args.approvalId);
    if (!doc) throw new Error("approval not found");
    if (doc.status === "applied") return { ok: true, alreadyApplied: true };
    await tx.db.patch(args.approvalId, {
      status: "applied",
      verdict: args.verdict,
      attackSteps: args.attackSteps,
      engineRunId: args.engineRunId,
      log: args.log,
      resolvedAt: Date.now(),
    });
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
