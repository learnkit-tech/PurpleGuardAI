import { RCE_FINDING } from "./rce";
import { SQLI_FINDING } from "./sqli";
import { TRAVERSAL_FINDING } from "./pathTraversal";
import type { EngineFinding } from "../ingest";

export const REAL_FINDINGS: EngineFinding[] = [
  SQLI_FINDING,
  RCE_FINDING,
  TRAVERSAL_FINDING,
];

export function toOrchestratorJson(findings: EngineFinding[]): string {
  return JSON.stringify(
    {
      schema: "purpleguard.findings/v1",
      generated_at: new Date().toISOString(),
      engine: "PurpleGuard orchestrator",
      findings: findings.map((f) => ({
        id: f.id,
        title: f.title,
        severity: f.severity,
        vulnerabilityType: f.vulnerabilityType,
        repo: f.repo,
        file: f.file,
        location: f.location,
        attackSurface: f.attackSurface,
        attackPath: f.attackPath,
        explanation: f.explanation,
        remediation: f.remediation,
        vulnerableCode: f.vulnerableCode,
        proposedPatch: f.proposedPatch,
        fixedCode: f.fixedCode,
        reTestChecks: f.reTestChecks,
        vulnerableMarker: f.vulnerableMarker,
        evidence: f.evidence,
        attackSteps: f.attackSteps,
        testerNote: f.testerNote,
        run: {
          run_id: f.runId,
          started_at: f.startedAt,
        },
      })),
    },
    null,
    2,
  );
}
