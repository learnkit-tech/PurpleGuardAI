import { v } from "convex/values";
import { internalMutation, mutation, query } from "./_generated/server";
import { getCurrentUser } from "./users";

/**
 * Projects known to PurpleGuard. Created lazily when a finding arrives
 * (engine ingest or Hacker handoff), registered explicitly via GitHub OAuth
 * (source "github"), or added manually (source "manual"). This is the
 * first-class entity every panel filters by.
 *
 * `source` ranks github > engine > handoff > manual and is never downgraded.
 */

const SOURCE_RANK: Record<string, number> = {
  github: 3,
  engine: 2,
  handoff: 1,
  manual: 0,
};

/** Shared ensure logic (no auth — callers enforce their own gates). */
async function ensureProject(
  ctx: { db: import("./_generated/server").MutationCtx["db"] },
  repo: string,
  source: string,
) {
  const existing = await ctx.db
    .query("projects")
    .withIndex("repo", (q) => q.eq("repo", repo))
    .unique();
  const now = Date.now();
  if (existing) {
    await ctx.db.patch(existing._id, {
      lastActivityAt: now,
      // Never downgrade a higher-ranked source.
      source:
        (SOURCE_RANK[source] ?? 0) > (SOURCE_RANK[existing.source] ?? 0)
          ? source
          : existing.source,
    });
    return existing._id;
  }
  return await ctx.db.insert("projects", {
    repo,
    source,
    firstSeenAt: now,
    lastActivityAt: now,
  });
}

/** Internal: used by the engine ingest path (X-Engine-Key routes). */
export const ensureFromEngine = internalMutation({
  args: { repo: v.string() },
  handler: async (ctx, args) => ensureProject(ctx, args.repo, "engine"),
});

/** Internal: called after verdict resolution updates a finding. */
export const touchInternal = internalMutation({
  args: { repo: v.string() },
  handler: async (ctx, args) => ensureProject(ctx, args.repo, "engine"),
});

/** Signed-in users only: used by the Hacker-panel handoff. */
export const ensureFromUi = mutation({
  args: { repo: v.string() },
  handler: async (ctx, args) => {
    const user = await getCurrentUser(ctx);
    if (user === null) throw new Error("Not authenticated");
    const id = await ensureProject(ctx, args.repo, "handoff");
    return { projectId: id };
  },
});

/**
 * Signed-in users only: register a project from the GitHub connect flow.
 * Called from the Console connect dialog after the user picks a repo; the
 * OAuth token lives only on the user row — it never reaches the client.
 */
export const connectGithub = mutation({
  args: {
    repo: v.string(),
    externalId: v.optional(v.number()),
    private: v.optional(v.boolean()),
  },
  handler: async (ctx, args) => {
    const user = await getCurrentUser(ctx);
    if (user === null) throw new Error("Not authenticated");
    if (!user.githubToken) {
      throw new Error(
        "GitHub is not connected for this account — start the connect flow first",
      );
    }
    const repo = args.repo.trim();
    if (!repo || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo)) {
      throw new Error("repo must look like owner/name");
    }
    const id = await ensureProject(ctx, repo, "github");
    await ctx.db.patch(id, {
      provider: "github",
      ...(args.externalId !== undefined ? { externalId: args.externalId } : {}),
      connectedBy: user._id,
      connectedAt: Date.now(),
      connectedLogin: user.githubLogin,
    });
    return { projectId: id };
  },
});

/**
 * Signed-in users only: register a project manually by identifier. Keeps the
 * "+ Connect Project" path usable before any OAuth/connector work for other
 * providers — the project is recorded with source "manual" and can be
 * upgraded later if a real connection lands.
 */
export const addManual = mutation({
  args: { repo: v.string() },
  handler: async (ctx, args) => {
    const user = await getCurrentUser(ctx);
    if (user === null) throw new Error("Not authenticated");
    const repo = args.repo.trim();
    if (!repo) throw new Error("Project identifier is required");
    const id = await ensureProject(ctx, repo, "manual");
    return { projectId: id };
  },
});

/** Signed-in users only. */
export const list = query({
  args: {},
  handler: async (ctx) => {
    const user = await getCurrentUser(ctx);
    if (user === null) return [];
    return await ctx.db.query("projects").withIndex("repo").collect();
  },
});
