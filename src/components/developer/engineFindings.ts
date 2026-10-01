import type { AttackStep, FindingDetailData } from "./data";

export interface ReTestResult {
  fixed: boolean;
  /** "engine" = verdict from orchestrator data; "fallback" = marker check. */
  source: "engine" | "fallback";
  log: string[];
}

/**
 * Replays the recorded attack path for a finding.
 *
 * Source of truth is the engine: each imported attack step carries a real
 * verdict recorded by the validator. The finding is VERIFIED FIXED only when
 * every step is "blocked". The marker substring check survives solely as a
 * fallback for built-in samples that have no engine data attached.
 */
export function runReTest(
  finding: FindingDetailData,
  code: string,
): ReTestResult {
  const log: string[] = [];
  log.push(
    `[validator] replaying authorized attack path for ${finding.id}`,
  );
  log.push(
    `[validator] target: ${finding.repo}/${finding.file} (${finding.location})`,
  );

  const steps: AttackStep[] | undefined = finding.attackSteps;

  if (steps && steps.length > 0) {
    log.push(
      `[engine] ${steps.length} recorded step(s) — verdicts come from the orchestrator run`,
    );
    for (const step of steps) {
      log.push(`[step] ${step.name} — ${step.criteria}`);
      for (const line of step.log) log.push(`  ${line}`);
      log.push(
        `[verdict] ${step.name}: ${step.verdict === "blocked" ? "BLOCKED" : "EXPLOITED"}`,
      );
    }
    const anyExploited = steps.some((s) => s.verdict === "exploitable");
    log.push(
      anyExploited
        ? "[result] at least one step still exploitable — attack succeeded"
        : "[result] every step blocked — attack path exhausted",
    );
    log.push(anyExploited ? "[verdict] STILL VULNERABLE" : "[verdict] VERIFIED FIXED");
    return { fixed: !anyExploited, source: "engine", log };
  }

  // Fallback: legacy sample findings without engine data.
  log.push(
    `[engine] no recorded steps — falling back to marker oracle for ${finding.id}`,
  );
  const stillVulnerable = code.includes(finding.vulnerableMarker);
  log.push(
    stillVulnerable
      ? `[result] marker "${finding.vulnerableMarker}" still present — attack succeeded`
      : `[result] marker "${finding.vulnerableMarker}" absent — attack path exhausted`,
  );
  log.push(stillVulnerable ? "[verdict] STILL VULNERABLE" : "[verdict] VERIFIED FIXED");
  return { fixed: !stillVulnerable, source: "fallback", log };
}
