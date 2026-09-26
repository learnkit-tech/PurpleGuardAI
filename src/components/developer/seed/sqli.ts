import type { EngineFinding } from "../ingest";

/** Verdicts recorded by the PurpleGuard validator during the authorized staging-mirror run. */
export const SQLI_FINDING: EngineFinding = {
  id: "F-2839",
  title: "SQL injection in /api/v2/orders search",
  severity: "high",
  vulnerabilityType: "SQL injection (string-concatenated query)",
  repo: "payments-core",
  file: "src/routes/orders.ts",
  location: "line 12",
  attackSurface: "Public REST API",
  attackPath: [
    "Fuzzing the q parameter on GET /api/v2/orders returns database errors for quote payloads",
    "Boolean-based blind injection confirmed: q=' OR '1'='1 returns the full order table",
    "UNION probe confirms table layout and exposes card_last4 column",
  ],
  explanation:
    "The search endpoint concatenates the untrusted q parameter directly into the SQL statement. The authorized validator extracted the full orders table using a boolean-based blind injection payload, demonstrating attacker-controlled query structure.",
  remediation:
    "Use a parameterized query (or the query builder's binding API) so user input can never change statement structure.",
  vulnerableCode: [
    'import { db } from "../db";',
    "",
    "export async function searchOrders(req: Request): Promise<Response> {",
    '  const q = new URL(req.url).searchParams.get("q") ?? "";',
    "  const rows = await db.all(",
    "    `SELECT id, customer, total_cents, card_last4 FROM orders WHERE customer LIKE '%${q}%'`,",
    "  );",
    "  return Response.json({ orders: rows });",
    "}",
  ].join("\n"),
  proposedPatch: [
    'import { db } from "../db";',
    "",
    "export async function searchOrders(req: Request): Promise<Response> {",
    '  const q = new URL(req.url).searchParams.get("q") ?? "";',
    "  const rows = await db.all(",
    '    "SELECT id, customer, total_cents, card_last4 FROM orders WHERE customer LIKE ?",',
    '    [`%${q}%`],',
    "  );",
    "  return Response.json({ orders: rows });",
    "}",
  ].join("\n"),
  fixedCode: [
    'import { db } from "../db";',
    "",
    "export async function searchOrders(req: Request): Promise<Response> {",
    '  const q = new URL(req.url).searchParams.get("q") ?? "";',
    "  const rows = await db.all(",
    '    "SELECT id, customer, total_cents, card_last4 FROM orders WHERE customer LIKE ?",',
    '    [`%${q}%`],',
    "  );",
    "  return Response.json({ orders: rows });",
    "}",
  ].join("\n"),
  reTestChecks: [
    "Payload q=' OR '1'='1 returns zero matches instead of the full table",
    "No raw interpolation reaches the SQL driver",
    "LIKE wildcard behavior preserved for normal searches",
  ],
  vulnerableMarker: "LIKE '%${q}%'",
  evidence: [
    {
      id: "F-2839-ev-1",
      kind: "http",
      label: "Request that triggered extraction",
      content: [
        "GET /api/v2/orders?q=' OR '1'='1 HTTP/1.1",
        "Host: api.payments.example",
        "",
        "HTTP/1.1 200 OK",
        "",
        '{ "orders": [ { "id": 1, "customer": "a", "card_last4": "4242" }, ... 18,402 more rows ] }',
      ].join("\n"),
    },
    {
      id: "F-2839-ev-2",
      kind: "log",
      label: "Validator timing probe",
      content:
        "[validator] boolean-blind oracle: quote payload changes row count 25 -> 18402 (confidence 0.99)",
    },
    {
      id: "F-2839-ev-3",
      kind: "scan",
      label: "Taint trace",
      content:
        'searchParams.get("q") -> orders.ts:12 -> template literal -> db.all() - no sanitizer on path',
    },
  ],
  testerNote:
    "Authorized validation against the staging mirror. Read-only probes; the UNION probe was limited to the first row.",
  attackSteps: [
    {
      name: "Boolean-blind probe q=' OR '1'='1",
      description: "Replay of the extraction payload against the current orders search implementation",
      criteria: "Row count stays at the baseline instead of returning the full orders table",
      verdict: "exploitable",
      log: [
        "[validator] baseline row count: 25",
        "[validator] payload row count: 18402",
        "[validator] full table extraction reproduced",
      ],
    },
    {
      name: "Taint check: interpolation reaches SQL driver",
      description: "Verify no raw request input is interpolated into the statement",
      criteria: "Statement structure is constant regardless of q",
      verdict: "exploitable",
      log: [
        "[validator] template literal feeding db.all()",
        "[validator] no binding layer on path",
      ],
    },
    {
      name: "LIKE semantics for benign searches",
      description: "Wildcard search behavior must be preserved by any fix",
      criteria: "Substring search still matches for normal queries",
      verdict: "exploitable",
      log: ["[validator] benign search 'acme' returned 12 rows (behavior check)"],
    },
  ],
  runId: "run-2026-09-24-payments-core-sqli-01",
  startedAt: "2026-09-24T09:12:04Z",
};
