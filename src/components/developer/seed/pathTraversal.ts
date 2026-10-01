import type { EngineFinding } from "../ingest";

const FIXED = [
  "import path from \"node:path\";",
  "import { readFile } from \"node:fs/promises\";",
  "",
  "const MIME: Record<string, string> = {",
  "  \".css\": \"text/css\",",
  "  \".js\": \"text/javascript\",",
  "  \".svg\": \"image/svg+xml\",",
  "};",
  "",
  "export async function serveAsset(root: string, name: string) {",
  "  const file = path.resolve(root, name);",
  "  if (!file.startsWith(path.resolve(root) + path.sep)) {",
  "    return new Response(\"Forbidden\", { status: 403 });",
  "  }",
  "  if (!MIME[path.extname(file)]) {",
  "    return new Response(\"Not Found\", { status: 404 });",
  "  }",
  "  const data = await readFile(file);",
  "  return new Response(data);",
  "}",
].join("\n");

const CHECKS = [
  "Traversal payload /assets/..%2f..%2fcanary.txt returns 403 instead of file contents",
  "Resolved path stays inside the assets root for every probe",
  "Legitimate assets still served with correct content types",
];

const MARKER = "path.join(root, name)";

const RUNID = "run-2026-09-24-edge-gateway-traversal-01";

const STARTED = "2026-09-24T07:58:22Z";

const NOTE =
  "Reads were limited to a planted canary inside the engagement scope. No environment files, credentials, or user data were accessed.";

const EVIDENCE = [
  {
    id: "F-2832-ev-1",
    kind: "http" as const,
    label: "Traversal probe — canary read",
    content: [
      "GET /assets/..%2f..%2fcanary.txt HTTP/1.1",
      "Host: edge.example",
      "",
      "HTTP/1.1 200 OK",
      "Content-Type: text/plain; charset=utf-8",
      "",
      "PG-CANARY-9931: read succeeded (planted file, engagement scope)",
    ].join("\n"),
  },
  {
    id: "F-2832-ev-2",
    kind: "log" as const,
    label: "Validator path resolution log",
    content: [
      "[validator] requested: /assets/..%2f..%2fcanary.txt",
      "[validator] resolved: /srv/edge/canary.txt (outside assets root)",
      "[validator] normalization skipped by handler — traversal confirmed",
    ].join("\n"),
  },
];

const STEPS = [
  {
    name: "Encoded traversal payload replay",
    description: "Replay /assets/..%2f..%2fcanary.txt against the current handler",
    criteria: "Request is rejected before any file outside the assets root is opened",
    verdict: "exploitable" as const,
    log: [
      "[validator] payload replayed against current build",
      "[validator] canary contents returned (read succeeded)",
    ],
  },
  {
    name: "Path containment under hostile names",
    description: "Probe with nested and mixed traversal variants",
    criteria: "Resolved path stays inside the assets root for every probe",
    verdict: "exploitable" as const,
    log: [
      "[validator] 14 variants tested, 14 escaped the assets root",
      "[validator] handler performs no normalization or prefix check",
    ],
  },
  {
    name: "Legitimate asset serving",
    description: "Confirm normal asset requests still work",
    criteria: "Real assets serve correctly with correct content types",
    verdict: "exploitable" as const,
    log: ["[validator] benign request /assets/app.css returned 200 (behavior check)"],
  },
];

export const TRAVERSAL_FINDING: EngineFinding = {
  id: "F-2832",
  title: "Path traversal file read in static asset route",
  severity: "high",
  vulnerabilityType: "Path traversal (CWE-22)",
  repo: "edge-gateway",
  file: "src/routes/assets.ts",
  location: "lines 6-13",
  attackSurface: "Edge gateway · /assets/* route",
  attackPath: [
    "Asset route joins the requested filename onto the assets root without validation",
    "Encoded sequences ../ escape the assets tree",
    "Validator read a canary file two directories above the assets root",
  ],
  explanation:
    "The static asset handler concatenates the raw filename parameter onto the assets directory and serves the result. Encoded parent-directory sequences are not normalized away, so request paths can escape the assets tree. The validator confirmed arbitrary file read within the authorization scope by reading a planted canary file.",
  remediation:
    "Normalize the joined path, require the result to stay inside the assets root, and serve only a fixed allowlist of content types.",
  vulnerableCode: [
    "import path from \"node:path\";",
    "import { readFile } from \"node:fs/promises\";",
    "",
    "export async function serveAsset(root: string, name: string) {",
    "  const file = path.join(root, name);",
    "  const data = await readFile(file);",
    "  return new Response(data);",
    "}",
  ].join("\n"),
  proposedPatch: [
    "import path from \"node:path\";",
    "import { readFile } from \"node:fs/promises\";",
    "",
    "const MIME: Record<string, string> = {",
    "  \".css\": \"text/css\",",
    "  \".js\": \"text/javascript\",",
    "  \".svg\": \"image/svg+xml\",",
    "};",
    "",
    "export async function serveAsset(root: string, name: string) {",
    "  const file = path.resolve(root, name);",
    "  if (!file.startsWith(path.resolve(root) + path.sep)) {",
    "    return new Response(\"Forbidden\", { status: 403 });",
    "  }",
    "  if (!MIME[path.extname(file)]) {",
    "    return new Response(\"Not Found\", { status: 404 });",
    "  }",
    "  const data = await readFile(file);",
    "  return new Response(data);",
    "}",
  ].join("\n"),
  fixedCode: FIXED,
  reTestChecks: CHECKS,
  vulnerableMarker: MARKER,
  evidence: EVIDENCE,
  testerNote: NOTE,
  attackSteps: STEPS,
  runId: RUNID,
  startedAt: STARTED,
};
