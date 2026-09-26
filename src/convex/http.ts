import { httpRouter } from "convex/server";
import { auth } from "./auth";
import {
  respondPreflight,
  ingestFinding,
  pendingApprovals,
  resolveApproval,
  pendingRevalidations,
  resolveRevalidation,
  pendingRuns,
  claimRun,
  resolveRun,
} from "./engineHttp";
import { githubStart, githubCallback } from "./githubHttp";

const http = httpRouter();

http.route({ path: "/api/ingest_finding", method: "POST", handler: ingestFinding });
http.route({ path: "/api/ingest_finding", method: "OPTIONS", handler: respondPreflight });

http.route({ path: "/api/approvals/pending", method: "GET", handler: pendingApprovals });
http.route({ path: "/api/approvals/pending", method: "OPTIONS", handler: respondPreflight });

http.route({ path: "/api/approvals/resolve", method: "POST", handler: resolveApproval });
http.route({ path: "/api/approvals/resolve", method: "OPTIONS", handler: respondPreflight });

http.route({ path: "/api/revalidate/pending", method: "GET", handler: pendingRevalidations });
http.route({ path: "/api/revalidate/pending", method: "OPTIONS", handler: respondPreflight });

http.route({ path: "/api/revalidate/resolve", method: "POST", handler: resolveRevalidation });
http.route({ path: "/api/revalidate/resolve", method: "OPTIONS", handler: respondPreflight });

http.route({ path: "/api/runs/pending", method: "GET", handler: pendingRuns });
http.route({ path: "/api/runs/pending", method: "OPTIONS", handler: respondPreflight });

http.route({ path: "/api/runs/claim", method: "POST", handler: claimRun });
http.route({ path: "/api/runs/claim", method: "OPTIONS", handler: respondPreflight });

http.route({ path: "/api/runs/resolve", method: "POST", handler: resolveRun });
http.route({ path: "/api/runs/resolve", method: "OPTIONS", handler: respondPreflight });

http.route({ path: "/api/github/start", method: "GET", handler: githubStart });
http.route({ path: "/api/github/callback", method: "GET", handler: githubCallback });

auth.addHttpRoutes(http);

export default http;
