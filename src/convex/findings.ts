import { v } from "convex/values";
import {
  internalMutation,
  mutation,
  query,
  type MutationCtx,
} from "./_generated/server";
import { getCurrentUser } from "./users";
import { internal } from "./_generated/api";

/**
 * Developer Panel findings, imported from orchestrator.py output.
 * The payload is stored opaquely; the UI re-validates it through
 * ingestFindings() when rendering, so partially-valid payloads degrade
 * gracefully instead of breaking the panel.
 *
 * Security model:
 * - `list` / `replaceAll` / `upsertFromUi` are called by the signed-in web
 *   app and verify the Convex auth session server-side.
 * - `ingestFromEngine` is called by the Python engine through
 *   /api/ingest_finding, which authenticates with X-Engine-Key. It is an
 *   internal mutation so it cannot be invoked directly from the client.
 */

/** Shared validation + upsert used by both ingest paths. */
async function upsertFinding(ctx: MutationCtx, payload: unknown) {
  const o = payload as Record<string, unknown>;
  const findingId = typeof o?.id === "string" ? o.id : "";
  if (!findingId) throw new Error("payload.id is required");
  const steps = Array.isArray(o.attackSteps) ? o.attackSteps : [];
  if (steps.length === 0) {
    throw new Error(
      "payload.attackSteps is required — reverification.py must record per-step blocked/exploitable verdicts",
    );
  }
  // Register/touch the project this finding belongs to (first-class entity).
  const repo = typeof o?.repo === "string" && o.repo ? o.repo : "unknown-repo";
  await ctx.runMutation(internal.projects.ensureFromEngine, { repo });
  const existing = await ctx.db
    .query("findings")
    .withIndex("findingId", (q) => q.eq("findingId", findingId))
    .unique();
  if (existing) {
    await ctx.db.patch(existing._id, {
      payload,
      importedAt: Date.now(),
    });
    return { findingId, updated: true };
  }
  await ctx.db.insert("findings", {
    findingId,
    importedAt: Date.now(),
    payload,
  });
  return { findingId, updated: false };
}

/** Signed-in users only. */
export const list = query({
  args: {},
  handler: async (ctx) => {
    const user = await getCurrentUser(ctx);
    if (user === null) return [];
    return await ctx.db.query("findings").withIndex("findingId").collect();
  },
});

/**
 * Single-finding ingest endpoint for orchestrator.py. Pushes one run's
 * finding; verdicts in attackSteps are the engine's recorded re-attack
 * results and are stored as-is. Rejects payloads without attackSteps so a
 * half-finished run can never produce a simulated-looking verdict.
 *
 * INTERNAL: reached only via /api/ingest_finding (X-Engine-Key).
 */
export const ingestFromEngine = internalMutation({
  args: { payload: v.any() },
  handler: async (ctx, args) => upsertFinding(ctx, args.payload),
});

/**
 * Signed-in users only: the Hacker panel's "Send to Developer" handoff.
 * Same validation rules as the engine ingest — attackSteps are mandatory.
 */
export const upsertFromUi = mutation({
  args: { payload: v.any() },
  handler: async (ctx, args) => {
    const user = await getCurrentUser(ctx);
    if (user === null) throw new Error("Not authenticated");
    return upsertFinding(ctx, args.payload);
  },
});

/** Signed-in users only: JSON upload from the Developer Panel. */
export const replaceAll = mutation({
  args: { payloads: v.array(v.any()) },
  handler: async (ctx, args) => {
    const user = await getCurrentUser(ctx);
    if (user === null) throw new Error("Not authenticated");
    for (const doc of await ctx.db.query("findings").withIndex("findingId").collect()) {
      await ctx.db.delete(doc._id);
    }
    const now = Date.now();
    for (const payload of args.payloads) {
      const findingId = typeof payload?.id === "string" ? payload.id : "";
      if (!findingId) continue;
      await ctx.db.insert("findings", {
        findingId,
        importedAt: now,
        payload,
      });
    }
    const count = await ctx.db
      .query("findings")
      .withIndex("findingId")
      .collect();
    return count.length;
  },
});
