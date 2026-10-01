import { httpAction } from "./_generated/server";
import { internal } from "./_generated/api";

/**
 * GitHub OAuth connect flow (Phase 2 — Main Console).
 *
 * These are top-level browser navigations to the Convex deployment origin
 * (https://<deployment>.convex.site), so they carry NO Convex auth session.
 * Identity binding therefore happens earlier:
 *
 *   1. The panel calls the authenticated mutation github.beginConnection
 *      (on the app origin, with the Convex session). It stores a single-use
 *      state row bound to the user id AND the app origin to return to.
 *   2. The panel redirects the browser to
 *      GET https://<deployment>.convex.site/api/github/start?state=<state>.
 *   3. githubStart (below) 302s to GitHub's authorize URL with that state.
 *   4. GitHub redirects to GET /api/github/callback?code=…&state=….
 *      githubCallback consumes the state (restoring the bound user id and
 *      return origin), exchanges the code for a token, stores the token on
 *      the bound user, and 302s back to <origin>/dashboard?github=…
 *
 * Without GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET every route reports the
 * flow as unavailable instead of failing silently (fail closed).
 */

export const githubStart = httpAction(async (ctx, request) => {
  const clientId = process.env.GITHUB_CLIENT_ID;
  const url = new URL(request.url);
  const state = url.searchParams.get("state");

  if (!clientId || !process.env.GITHUB_CLIENT_SECRET) {
    // Without OAuth credentials we cannot know where the browser came from
    // (the state row may still exist, but the safest honest response is a
    // plain error page describing the misconfiguration).
    return new Response(
      "GitHub OAuth is not configured on this deployment (GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET missing).",
      { status: 503, headers: { "Content-Type": "text/plain" } },
    );
  }
  if (!state) {
    return new Response(
      "Missing state parameter — start the connect flow from the PurpleGuard Console.",
      { status: 400, headers: { "Content-Type": "text/plain" } },
    );
  }

  const authorize = new URL("https://github.com/login/oauth/authorize");
  authorize.searchParams.set("client_id", clientId);
  authorize.searchParams.set("scope", "repo read:org");
  authorize.searchParams.set("state", state);
  return new Response(null, {
    status: 302,
    headers: { Location: authorize.toString() },
  });
});

export const githubCallback = httpAction(async (ctx, request) => {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const ghError = url.searchParams.get("error");

  // GitHub may also surface errors through error/error_description params.
  if (ghError) {
    const desc = url.searchParams.get("error_description") ?? ghError;
    return new Response(
      `GitHub denied the connect request: ${desc}. Close this tab and try again from the PurpleGuard Console.`,
      { status: 400, headers: { "Content-Type": "text/plain" } },
    );
  }
  if (!code || !state) {
    return new Response(
      "Missing code or state parameter — start the connect flow from the PurpleGuard Console.",
      { status: 400, headers: { "Content-Type": "text/plain" } },
    );
  }

  try {
    // completeConnection consumes the state row and returns the app origin
    // captured when the connect started, so the redirect goes back to the
    // real app (the vly.sh preview), never to the deployment origin.
    const result = await ctx.runMutation(internal.github.completeConnection, {
      state,
      code,
    });
    const target = new URL("/dashboard", result.origin);
    target.searchParams.set("github", "connected");
    return new Response(null, {
      status: 302,
      headers: { Location: target.toString() },
    });
  } catch (e) {
    const message = e instanceof Error ? e.message : "GitHub connection failed";
    // The state row carries the origin; on failure the mutation may have
    // already consumed it, so fall back to serving the error plainly.
    return new Response(
      `GitHub connection failed: ${message}. Close this tab and try again from the PurpleGuard Console.`,
      { status: 400, headers: { "Content-Type": "text/plain" } },
    );
  }
});
