import { cronJobs } from "convex/server";
import { internalMutation } from "./_generated/server";
import { internal } from "./_generated/api";

/**
 * Phase 3: scheduled re-validation. Once a day, queue a re-validation run
 * for every known project. This is REAL queued work the engine picks up via
 * /api/runs/pending — not a simulation. De-duped per project: if a run for
 * the project is already queued or running, the cron skips it.
 */
export const queueDailyRevalidations = internalMutation({
  args: {},
  handler: async (ctx) => {
    const projects = await ctx.db.query("projects").collect();
    const runs = await ctx.db.query("workflowRuns").collect();
    const active = new Set(
      runs
        .filter((r) => r.status === "queued" || r.status === "running")
        .map((r) => r.projectId),
    );

    let queued = 0;
    const now = Date.now();
    for (const p of projects) {
      if (active.has(p.repo)) continue;
      await ctx.db.insert("workflowRuns", {
        projectId: p.repo,
        kind: "revalidation",
        status: "queued",
        note: "Daily scheduled re-validation",
        createdAt: now,
        updatedAt: now,
      });
      queued += 1;
    }
    if (queued > 0) {
      console.log(`[crons] queued ${queued} scheduled re-validation run(s)`);
    }
    return { queued };
  },
});

const crons = cronJobs();

// Phase 3: scheduled re-validation. Every day at 03:00 UTC, queue a
// re-validation run for every known project (de-duped, above). The engine
// picks these up via /api/runs/pending like any other queued run.
crons.daily(
  "daily-revalidation",
  { hourUTC: 3, minuteUTC: 0 },
  internal.crons.queueDailyRevalidations,
);

// Housekeeping: drop expired GitHub OAuth CSRF states (single-use rows with
// a 10-minute TTL; anything left over is dead weight).
crons.daily(
  "oauth-state-cleanup",
  { hourUTC: 3, minuteUTC: 30 },
  internal.github.deleteExpiredStates,
);

export default crons;
