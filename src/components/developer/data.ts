/**
 * Developer Panel domain types: findings produced by the authorized
 * security-validation loop, their code, evidence, and re-test verdicts.
 *
 * Product truth encoded here: a finding is not closed until PurpleGuard
 * re-runs the authorized attack and proves it no longer succeeds.
 *
 * Note: the legacy built-in fixture array that lived in this file was
 * removed — `seed/` (with recorded engine attack steps) is the single
 * fallback data source, and re-test replay lives in `engineFindings.ts`.
 */

import type { Severity } from "@/components/landing/data";

export type { Severity };

export type VerificationState =
  | "unverified" // attack path not re-tested yet
  | "vulnerable" // re-test succeeded — still exploitable
  | "verified"; // re-test failed — issue proven fixed

export type FixSource = "manual" | "ai" | null;

/**
 * One step of the authorized attack path, with the REAL verdict the engine
 * recorded when it re-ran this step. Ingested from orchestrator.py output.
 */
export interface AttackStep {
  name: string;
  description: string;
  /** What counts as a pass for this step. */
  criteria: string;
  verdict: "exploitable" | "blocked";
  /** Validator log lines captured during the re-attack. */
  log: string[];
}

export interface EvidenceItem {
  id: string;
  kind: "http" | "code" | "log" | "scan";
  label: string;
  /** Full payload / snippet / log line shown in the evidence viewer. */
  content: string;
}

export interface FindingDetailData {
  id: string;
  title: string;
  severity: Severity;
  vulnerabilityType: string;
  repo: string;
  file: string;
  location: string;
  attackSurface: string;
  attackPath: string[];
  explanation: string;
  remediation: string;
  /** Original (vulnerable) code shipped with the finding. */
  vulnerableCode: string;
  /** Patch ECC proposes. Applying it yields `fixedCode`. */
  proposedPatch: string;
  fixedCode: string;
  /** What the validator checks when re-running the authorized attack. */
  reTestChecks: string[];
  /**
   * Real engine attack steps with recorded verdicts. Present for findings
   * imported from orchestrator.py; absent for built-in samples.
   */
  attackSteps?: AttackStep[];
  /** Which single substring must disappear for the re-test to pass. */
  vulnerableMarker: string;
  evidence: EvidenceItem[];
  testerNote: string;
}

export interface FindingState {
  /** Current code in the workspace (starts as the vulnerable version). */
  code: string;
  verification: VerificationState;
  fixSource: FixSource;
  /** Log of applied modifications, newest last. */
  history: Array<{
    at: number;
    source: Exclude<FixSource, null>;
    summary: string;
    fixed: boolean;
  }>;
  attempts: number;
}

export function initialState(finding: FindingDetailData): FindingState {
  return {
    code: finding.vulnerableCode,
    verification: "unverified",
    fixSource: null,
    history: [],
    attempts: 0,
  };
}
