import { authTables } from "@convex-dev/auth/server";
import { defineSchema, defineTable } from "convex/server";
import { Infer, v } from "convex/values";

// default user roles. can add / remove based on the project as needed
export const ROLES = {
  ADMIN: "admin",
  USER: "user",
  MEMBER: "member",
} as const;

export const roleValidator = v.union(
  v.literal(ROLES.ADMIN),
  v.literal(ROLES.USER),
  v.literal(ROLES.MEMBER),
);
export type Role = Infer<typeof roleValidator>;

const schema = defineSchema(
  {
    // default auth tables using convex auth.
    ...authTables, // do not remove or modify

    // the users table is the default users table that is brought in by the authTables
    users: defineTable({
      name: v.optional(v.string()), // name of the user. do not remove
      image: v.optional(v.string()), // image of the user. do not remove
      email: v.optional(v.string()), // email of the user. do not remove
      emailVerificationTime: v.optional(v.number()), // email verification time. do not remove
      isAnonymous: v.optional(v.boolean()), // is the user anonymous. do not remove

      role: v.optional(roleValidator), // role of the user. do not remove

      // GitHub connection (Phase 2). The OAuth access token is stored
      // server-side only — it is never sent to the client. Fail-closed:
      // without GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET these stay unset.
      githubToken: v.optional(v.string()),
      githubLogin: v.optional(v.string()),
      githubConnectedAt: v.optional(v.number()),
    }).index("email", ["email"]), // index for the email. do not remove or modify

    // add other tables here

    /**
     * Findings imported from the PurpleGuard orchestrator (orchestrator.py).
     * `attackSteps[].verdict` is the REAL re-attack verdict recorded by the
     * validator — the panel must never invent these.
     */
    findings: defineTable({
      findingId: v.string(),
      ownerToken: v.optional(v.string()),
      importedAt: v.number(),
      payload: v.any(), // full EngineFinding JSON (shape per purpleguard.findings/v1)
    }).index("findingId", ["findingId"]),

    /**
     * Approve-and-apply requests from the Developer Panel. The engine polls
     * pending approvals, applies the approved code, re-attacks, and records
     * the real verdict back here — which also updates the finding's
     * attackSteps so the panel reflects the latest engine run.
     */
    approvals: defineTable({
      findingId: v.string(),
      source: v.string(), // "ai" | "manual"
      code: v.string(), // approved workspace code the engine should apply
      status: v.string(), // "pending" | "applied"
      engineRunId: v.optional(v.string()),
      verdict: v.optional(v.string()), // "VERIFIED_FIXED" | "STILL_VULNERABLE"
      attackSteps: v.optional(
        v.array(
          v.object({
            name: v.string(),
            verdict: v.string(), // "blocked" | "exploitable"
          }),
        ),
      ),
      log: v.optional(v.array(v.string())),
      requestedAt: v.number(),
      resolvedAt: v.optional(v.number()),
    })
      .index("status", ["status"])
      .index("findingId", ["findingId"]),

    /**
     * Projects known to PurpleGuard. Created lazily when a finding arrives
     * (engine ingest or Hacker handoff) keyed by the repo identifier; the
     * Console, Hacker, Developer, and ECC panels all filter by this entity.
     * Since Phase 2 a project can also be registered explicitly: connected
     * via first-party GitHub OAuth (source "github") or added manually
     * (source "manual"). `source` ranks: github > engine > handoff > manual
     * and is never downgraded.
     */
    projects: defineTable({
      repo: v.string(),
      // "github" | "engine" | "handoff" | "manual" — never downgraded.
      source: v.string(),
      firstSeenAt: v.number(),
      lastActivityAt: v.number(),

      // GitHub connection details (present when source is "github").
      provider: v.optional(v.string()), // "github"
      externalId: v.optional(v.number()), // GitHub repo id
      connectedBy: v.optional(v.id("users")),
      connectedAt: v.optional(v.number()),
      connectedLogin: v.optional(v.string()),
    }).index("repo", ["repo"]),

    /**
     * Workflow runs tracking the security loop (validation, re-validation).
     * Status: "queued" | "claimed" | "running" | "completed" | "failed".
     *
     * Since Phase 3, queued runs are REAL executable work: the engine polls
     * /api/runs/pending, claims a run (with scope), executes the authorized
     * validation, ingests findings via /api/ingest_finding, and posts the
     * outcome back via /api/runs/resolve.
     *
     * `scope` carries the authorization artifacts the run is limited to
     * (authorized paths and blocked paths) so the engine never validates
     * outside granted scope. The panel must never present a queued run as a
     * completed scan.
     */
    workflowRuns: defineTable({
      projectId: v.string(), // matches projects.repo
      kind: v.string(), // "validation" | "revalidation"
      status: v.string(),
      requestedBy: v.optional(v.id("users")),
      engineRunId: v.optional(v.string()),
      note: v.optional(v.string()),
      /** Authorization artifacts limiting what the engine may test. */
      scope: v.optional(
        v.object({
          authorizedPaths: v.array(v.string()),
          blockedPaths: v.optional(v.array(v.string())),
        }),
      ),
      /** Set by the engine on resolve when it ingested new findings. */
      findingsIngested: v.optional(v.number()),
      createdAt: v.number(),
      updatedAt: v.number(),
    })
      .index("projectId", ["projectId"])
      .index("status", ["status"]),

    /**
     * Short-lived CSRF states for the GitHub OAuth connect flow (Phase 2).
     * Rows are single-use and expire; the callback route verifies the
     * `state` query param against this table before exchanging the code.
     *
     * The row ALSO carries the identity binding: the signed-in PurpleGuard
     * user who started the connect (resolved server-side via Convex auth
     * when beginConnection ran) and the app origin the browser came from.
     * The OAuth callback is a top-level browser navigation to the Convex
     * deployment origin, so it carries NO Convex auth session — identity
     * must be restored from this row, never guessed there.
     */
    oauthStates: defineTable({
      state: v.string(),
      // Signed-in user who initiated the connect — bound at mint time.
      userId: v.id("users"),
      // App origin (no trailing slash) to return the browser to after the
      // callback — captured at mint time from the Origin/Referer header.
      origin: v.string(),
      createdAt: v.number(),
      expiresAt: v.number(),
    }).index("state", ["state"]),

    /**
     * "Re-run validation" requests for engine-backed findings. The panel
     * queues one; the engine polls /api/revalidate/pending, re-attacks, and
     * posts the real verdict back via /api/revalidate/resolve.
     */
    revalidations: defineTable({
      findingId: v.string(),
      status: v.string(), // "pending" | "resolved"
      verdict: v.optional(v.string()), // "VERIFIED_FIXED" | "STILL_VULNERABLE"
      attackSteps: v.optional(
        v.array(
          v.object({
            name: v.string(),
            verdict: v.string(), // "blocked" | "exploitable"
          }),
        ),
      ),
      engineRunId: v.optional(v.string()),
      log: v.optional(v.array(v.string())),
      requestedAt: v.number(),
      resolvedAt: v.optional(v.number()),
    })
      .index("status", ["status"])
      .index("findingId", ["findingId"]),

    // tableName: defineTable({
    //   ...
    //   // table fields
    // }).index("by_field", ["field"])
  },
  {
    schemaValidation: false,
  },
);

export default schema;
