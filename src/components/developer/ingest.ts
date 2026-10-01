import type { AttackStep, EvidenceItem, Severity, FindingDetailData } from "./data";

/**
 * Tolerant ingest for orchestrator.py JSON. Unknown fields are ignored,
 * missing optionals get sane fallbacks, and malformed entries are skipped
 * with a reported error instead of breaking the panel.
 */

export interface RawEvidence {
  id?: unknown;
  kind?: unknown;
  label?: unknown;
  content?: unknown;
}

export interface RawStep {
  name?: unknown;
  description?: unknown;
  criteria?: unknown;
  verdict?: unknown;
  log?: unknown;
}

export interface RawRun {
  run_id?: unknown;
  runId?: unknown;
  started_at?: unknown;
  startedAt?: unknown;
  finished_at?: unknown;
  finishedAt?: unknown;
}

export interface RawFinding {
  id?: unknown;
  title?: unknown;
  severity?: unknown;
  vulnerabilityType?: unknown;
  repo?: unknown;
  file?: unknown;
  location?: unknown;
  attackSurface?: unknown;
  attackPath?: unknown;
  explanation?: unknown;
  remediation?: unknown;
  vulnerableCode?: unknown;
  proposedPatch?: unknown;
  fixedCode?: unknown;
  reTestChecks?: unknown;
  vulnerableMarker?: unknown;
  evidence?: unknown;
  attackSteps?: unknown;
  testerNote?: unknown;
  run?: unknown;
}

export interface EngineFinding extends FindingDetailData {
  attackSteps: AttackStep[];
  runId: string;
  startedAt: string;
}

export interface IngestResult {
  findings: EngineFinding[];
  errors: string[];
}

const SEVERITIES = ["critical", "high", "medium", "low"];
const KINDS = ["http", "code", "log", "scan"];

const isObj = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

const str = (v: unknown, fallback = ""): string =>
  typeof v === "string" ? v : fallback;

const strList = (v: unknown): string[] =>
  Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];

function severity(raw: unknown): Severity {
  const s = str(raw).toLowerCase();
  return (SEVERITIES as readonly string[]).includes(s)
    ? (s as Severity)
    : "medium";
}

function evidence(raw: unknown, id: string): EvidenceItem[] {
  if (!Array.isArray(raw)) return [];
  const out: EvidenceItem[] = [];
  raw.forEach((item, i) => {
    if (!isObj(item)) return;
    const content = str(item.content);
    if (!content) return;
    const kind = str(item.kind).toLowerCase();
    out.push({
      id: str(item.id) || `${id}-ev-${i + 1}`,
      kind: ((KINDS as readonly string[]).includes(kind)
        ? kind
        : "log") as EvidenceItem["kind"],
      label: str(item.label) || `Evidence ${i + 1}`,
      content,
    });
  });
  return out;
}

function steps(raw: unknown, checks: string[]): AttackStep[] {
  if (Array.isArray(raw)) {
    const out: AttackStep[] = [];
    raw.forEach((item, i) => {
      if (!isObj(item)) return;
      const name = str(item.name) || str(item.description) || `Step ${i + 1}`;
      out.push({
        name,
        description: str(item.description) || name,
        criteria: str(item.criteria) || checks[i] || name,
        verdict: item.verdict === "blocked" ? "blocked" : "exploitable",
        log: strList(item.log),
      });
    });
    return out;
  }
  // No explicit steps: synthesize one per recorded re-test check.
  return checks.map((c) => ({
    name: c,
    description: c,
    criteria: c,
    verdict: "exploitable",
    log: [],
  }));
}

export function ingestFindings(input: unknown): IngestResult {
  const errors: string[] = [];
  const findings: EngineFinding[] = [];

  let list: unknown[] = [];
  if (Array.isArray(input)) {
    list = input;
  } else if (isObj(input)) {
    if (Array.isArray(input.findings)) {
      list = input.findings;
    } else if (isObj(input.finding)) {
      list = [input.finding];
    } else {
      list = [input];
    }
  }

  list.forEach((entry, index) => {
    if (!isObj(entry)) {
      errors.push(`Entry ${index + 1} is not an object — skipped.`);
      return;
    }
    const o = entry as RawFinding;
    const checks = strList(o.reTestChecks);
    const rawSteps = o.attackSteps;
    const hasRealSteps = Array.isArray(rawSteps) && rawSteps.length > 0;
    const id = str(o.id) || `F-IMPORT-${index + 1}`;

    const attackSteps = steps(rawSteps, checks);
    const proposedPatch = str(o.proposedPatch) || str(o.vulnerableCode);
    const fixedCode = str(o.fixedCode) || proposedPatch;
    const run = isObj(o.run) ? (o.run as RawRun) : undefined;

    if (!hasRealSteps && attackSteps.length === 0) {
      errors.push(
        `${id}: no attackSteps or reTestChecks — re-test verdict would be invented, skipping.`,
      );
      return;
    }

    findings.push({
      id,
      title: str(o.title) || `${id} (untitled)`,
      severity: severity(o.severity),
      vulnerabilityType: str(o.vulnerabilityType) || "Unclassified vulnerability",
      repo: str(o.repo) || "unknown-repo",
      file: str(o.file) || "unknown.ts",
      location: str(o.location) || "—",
      attackSurface: str(o.attackSurface) || "—",
      attackPath: strList(o.attackPath),
      explanation: str(o.explanation) || "No explanation provided by the engine.",
      remediation: str(o.remediation) || "No remediation guidance provided.",
      vulnerableCode: str(o.vulnerableCode),
      proposedPatch,
      fixedCode,
      reTestChecks: attackSteps.map((s) => s.criteria),
      vulnerableMarker: str(o.vulnerableMarker),
      evidence: evidence(o.evidence, id),
      testerNote: str(o.testerNote) || "Authorized validation by the PurpleGuard engine.",
      attackSteps,
      runId: str(run?.run_id ?? run?.runId),
      startedAt: str(run?.started_at ?? run?.startedAt),
    });
  });

  return { findings, errors };
}
