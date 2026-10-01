import { v } from "convex/values";
import { internalMutation, mutation, query } from "./_generated/server";
import { getCurrentUser } from "./users";

/**
 * GitHub app connection (Phase 2 — Main Console).
 *
 * The OAuth access token is stored only on the user row (schema: users).
 * It is never returned to the client — the client only sees whether a
 * connection exists and the login name. All GitHub REST calls happen
 * server-side here; without GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET the
 * flow is unavailable and every route reports that honestly (fail closed).
 *
 * Flow (see githubHttp.ts):
 *   1. Panel calls `github.beginConnection` (authenticated Convex mutation).
 *      It mints a single-use CSRF state bound to the signed-in user AND the
 *      app origin the panel is running on, stores it in oauthStates, and
 *      returns the state.
 *   2. Panel redirects the browser to
 *      `https://<deployment>.convex.site/api/github/start?state=…`.
 *   3. githubStart 302s to GitHub's authorize URL with that state.
 *   4. GitHub redirects to /api/github/callback. This top-level navigation
 *      carries NO Convex auth session (the session cookie/localStorage lives
 *      on the app origin), so `completeConnection` restores the user from
 *      the stored state row instead of guessing identity there.
 *   5. Token exchange → token stored on the bound user → 302 back to the
 *      stored app origin at /dashboard?github=connected|error=…
 */

const STATE_TTL_MS = 10 * 60 * 1000;

/**
 * Signed-in users only: mint a single-use OAuth state for this user. The
 * state row carries the user id (identity binding) and the app origin the
 * connect was started from (return destination for the callback).
 */
export const beginConnection = mutation({
  args: { origin: v.string() },
  handler: async (ctx, args) => {
    const user = await getCurrentUser(ctx);
    if (user === null) throw new Error("Not authenticated");
    const origin = args.origin.trim().replace(/\/+$/, "");
    if (!/^https?:\/\//.test(origin)) {
      throw new Error("origin must be an absolute http(s) URL");
    }
    const now = Date.now();
    const state =
      crypto.randomUUID().replace(/-/g, "") +
      crypto.randomUUID().replace(/-/g, "");
    await ctx.db.insert("oauthStates", {
      state,
      userId: user._id,
      origin,
      createdAt: now,
      expiresAt: now + STATE_TTL_MS,
    });
    return { state };
  },
});

/**
 * INTERNAL: reached only via /api/github/callback. Verifies and consumes the
 * state, restores the bound user (the callback navigation has no auth
 * session), exchanges the code for an access token, validates it, and
 * stores it on that user.
 */
export const completeConnection = internalMutation({
  args: { state: v.string(), code: v.string() },
  handler: async (ctx, args) => {
    // 1. Verify + consume the CSRF state (single use).
    const row = await ctx.db
      .query("oauthStates")
      .withIndex("state", (q) => q.eq("state", args.state))
      .unique();
    if (!row) throw new Error("Unknown or already-used oauth state");
    await ctx.db.delete(row._id);
    if (row.expiresAt < Date.now()) throw new Error("OAuth state expired — start again");

    // 2. Fail closed if the OAuth app is not configured.
    const clientId = process.env.GITHUB_CLIENT_ID;
    const clientSecret = process.env.GITHUB_CLIENT_SECRET;
    if (!clientId || !clientSecret) {
      throw new Error(
        "GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET are not configured on this deployment",
      );
    }

    // 3. Exchange the code for an access token.
    const res = await fetch("https://github.com/login/oauth/access_token", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({
        client_id: clientId,
        client_secret: clientSecret,
        code: args.code,
      }),
    });
    if (!res.ok) throw new Error(`GitHub token exchange failed (${res.status})`);
    const data = (await res.json()) as {
      access_token?: string;
      error?: string;
      error_description?: string;
    };
    if (!data.access_token) {
      throw new Error(
        data.error_description ?? data.error ?? "GitHub returned no access token",
      );
    }

    // 4. Identify the GitHub account behind the token (also validates it).
    const userRes = await fetch("https://api.github.com/user", {
      headers: {
        Authorization: `Bearer ${data.access_token}`,
        Accept: "application/vnd.github+json",
        "User-Agent": "PurpleGuard-AI",
      },
    });
    if (!userRes.ok) throw new Error(`GitHub user lookup failed (${userRes.status})`);
    const ghUser = (await userRes.json()) as { login?: string };
    if (!ghUser.login) throw new Error("GitHub user response missing login");

    // 5. Attach to the bound user (NOT a session guess — the callback
    //    navigation carries no Convex auth session).
    await ctx.db.patch(row.userId, {
      githubToken: data.access_token,
      githubLogin: ghUser.login,
      githubConnectedAt: Date.now(),
    });
    // Hand the stored return origin back to the callback route so it can
    // 302 the browser to the real app.
    return { login: ghUser.login, origin: row.origin };
  },
});

/** Signed-in users only: does this account have GitHub connected? */
export const connectionStatus = query({
  args: {},
  handler: async (ctx) => {
    const user = await getCurrentUser(ctx);
    if (user === null) return { connected: false, login: null };
    return {
      connected: Boolean(user.githubToken),
      login: user.githubLogin ?? null,
    };
  },
});

/** Signed-in users only: disconnect GitHub and clear the stored token. */
export const disconnect = mutation({
  args: {},
  handler: async (ctx) => {
    const user = await getCurrentUser(ctx);
    if (user === null) throw new Error("Not authenticated");
    await ctx.db.patch(user._id, {
      githubToken: undefined,
      githubLogin: undefined,
      githubConnectedAt: undefined,
    });
    return { ok: true };
  },
});

export interface GithubRepo {
  id: number;
  fullName: string;
  private: boolean;
  defaultBranch: string;
  description?: string;
}

/**
 * Signed-in users only: list repos accessible with the stored token, with
 * whether PurpleGuard already tracks them as projects. Server-side GitHub
 * REST call — the token never leaves the Convex runtime.
 */
export const listRepos = query({
  args: {},
  handler: async (ctx) => {
    const user = await getCurrentUser(ctx);
    if (user === null || !user.githubToken) {
      return { repos: [] as GithubRepo[], connected: false, error: undefined };
    }
    const res = await fetch(
      "https://api.github.com/user/repos?sort=updated&per_page=30&affiliation=owner,collaborator",
      {
        headers: {
          Authorization: `Bearer ${user.githubToken}`,
          Accept: "application/vnd.github+json",
          "User-Agent": "PurpleGuard-AI",
        },
      },
    );
    if (!res.ok) {
      // Fail soft: the token may be revoked/expired; the panel shows why.
      return {
        repos: [] as GithubRepo[],
        connected: true,
        error: `GitHub API error ${res.status} — try reconnecting`,
      };
    }
    const repos = (await res.json()) as Array<{
      id: number;
      full_name: string;
      private: boolean;
      default_branch?: string;
      description?: string | null;
    }>;
    return {
      repos: repos.map<GithubRepo>((r) => ({
        id: r.id,
        fullName: r.full_name,
        private: r.private,
        defaultBranch: r.default_branch ?? "main",
        description: r.description ?? undefined,
      })),
      connected: true,
      error: undefined,
    };
  },
});

/** Cleanup helper for the daily cron: delete expired oauth states. */
export const deleteExpiredStates = internalMutation({
  args: {},
  handler: async (ctx) => {
    const now = Date.now();
    const rows = await ctx.db
      .query("oauthStates")
      .withIndex("state")
      .collect();
    let deleted = 0;
    for (const row of rows) {
      if (row.expiresAt < now) {
        await ctx.db.delete(row._id);
        deleted += 1;
      }
    }
    return { deleted };
  },
});
