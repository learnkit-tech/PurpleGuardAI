import { useMutation, useQuery } from "convex/react";
import { useCallback } from "react";
import { api } from "@/convex/_generated/api";

/**
 * Client-side view of the GitHub connection (Phase 2 — Main Console).
 *
 * The OAuth token never reaches the client: this hook only exposes whether
 * a connection exists, the login name, and the server-side repo listing.
 *
 * Connect flow (identity is bound before the browser leaves the app):
 *   1. `beginConnection` (authenticated mutation) mints a single-use state
 *      bound to the signed-in user and stores this window's origin as the
 *      callback return destination.
 *   2. Redirect the browser to the Convex deployment origin's
 *      /api/github/start?state=… — an absolute URL, because the HTTP routes
 *      do NOT live on the app origin. VITE_CONVEX_URL is https://…convex.cloud
 *      for queries/mutations; the sibling *.convex.site origin serves /api/*.
 *   3. GitHub sends the browser back to <stored origin>/dashboard?github=…
 */
export function useGithubConnection() {
  const status = useQuery(api.github.connectionStatus);
  const reposResult = useQuery(api.github.listRepos);
  const doDisconnect = useMutation(api.github.disconnect);
  const beginConnection = useMutation(api.github.beginConnection);

  const connect = useCallback(async () => {
    // Bind identity + return origin server-side first (fails fast when
    // signed out — before we ever leave the page).
    const { state } = await beginConnection({ origin: window.location.origin });
    const cloudUrl = import.meta.env.VITE_CONVEX_URL as string;
    // https://expert-elk-927.convex.cloud → https://expert-elk-927.convex.site
    const siteUrl = cloudUrl.replace(/\.convex\.cloud/, ".convex.site");
    // Full-page redirect out of the app; GitHub sends the user back to the
    // stored origin at /dashboard?github=connected|error=…
    window.location.href = `${siteUrl}/api/github/start?state=${encodeURIComponent(state)}`;
  }, [beginConnection]);

  const disconnect = useCallback(async () => {
    await doDisconnect({});
  }, [doDisconnect]);

  return {
    /** undefined while the query loads. */
    status,
    repos: reposResult?.repos ?? [],
    reposError: reposResult?.error,
    connected: status?.connected ?? false,
    login: status?.login ?? null,
    loading: status === undefined || reposResult === undefined,
    connect,
    disconnect,
  };
}
