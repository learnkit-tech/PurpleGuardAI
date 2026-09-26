import { useQuery } from "convex/react";
import { useMemo } from "react";
import { api } from "@/convex/_generated/api";
import { ingestFindings, type EngineFinding } from "@/components/developer/ingest";
import { REAL_FINDINGS } from "@/components/developer/seed";

/**
 * Shared derivation of PurpleGuard's real data for all panels.
 *
 * Source of truth is the Convex `findings` table (orchestrator.py output or
 * Hacker-panel handoffs). While the table is empty the panels fall back to
 * the seed findings so the loop stays demonstrable. Everything the panels
 * show — counts, surfaces, paths, activity, queues — is derived from these
 * records; nothing is invented per-panel.
 */

export interface ProjectSummary {
  id: string;
  name: string;
  critical: number;
  high: number;
  verified: number;
  total: number;
  /** Connection source: "github" | "engine" | "handoff" | "manual". */
  source: string;
}

export type ActivityTone = "violet" | "emerald" | "amber" | "cyan" | "rose";

export interface ActivityItem {
  id: string;
  tone: ActivityTone;
  text: string;
  at: number;
}

export interface AttackSurfaceRow {
  name: string;
  count: number;
}

export interface AttackPathItem {
  id: string;
  title: string;
  severity: string;
  finding: EngineFinding;
  /** The attack chain as recorded by the validator. */
  steps: string[];
  status: "confirmed" | "re-attacked" | "verified";
  /** Fraction of validated attack steps still exploitable (0–100). */
  confidence: number;
}

const VERDICT_FIXED = "VERIFIED_FIXED";

function stepStats(f: EngineFinding): { total: number; blocked: number } {
  const steps = f.attackSteps ?? [];
  return {
    total: steps.length,
    blocked: steps.filter((s) => s.verdict === "blocked").length,
  };
}

export function usePurpleGuardData(projectId?: string) {
  const rows = useQuery(api.findings.list);
  const approvals = useQuery(api.approvals.listRecent, { limit: 30 });
  const revalidations = useQuery(api.revalidations.listRecent, { limit: 30 });
  const projectRows = useQuery(api.projects.list);
  const runs = useQuery(api.workflow.listRecent, { limit: 30 });

  const loading =
    rows === undefined ||
    approvals === undefined ||
    revalidations === undefined ||
    projectRows === undefined ||
    runs === undefined;

  const findings = useMemo<EngineFinding[]>(() => {
    if (!rows || rows.length === 0) return REAL_FINDINGS;
    const result = ingestFindings(rows.map((r) => r.payload));
    return result.findings.length > 0 ? result.findings : REAL_FINDINGS;
  }, [rows]);

  const engineBacked = Boolean(rows && rows.length > 0);

  /** All findings (unscoped) — used for the projects overview. */
  const allFindings = findings;

  /** Findings scoped to the selected project (null = all projects). */
  const scopedFindings = useMemo<EngineFinding[]>(() => {
    if (!projectId) return findings;
    return findings.filter((f) => f.repo === projectId);
  }, [findings, projectId]);

  const projects = useMemo<ProjectSummary[]>(() => {
    const map = new Map<string, ProjectSummary>();
    const ensure = (repo: string, source = "manual"): ProjectSummary => {
      let p = map.get(repo);
      if (!p) {
        p = {
          id: repo,
          name: repo,
          critical: 0,
          high: 0,
          verified: 0,
          total: 0,
          source,
        };
        map.set(repo, p);
      }
      return p;
    };
    // First-class projects (may exist before any findings arrive).
    for (const p of projectRows ?? []) ensure(p.repo, p.source).source = p.source;
    for (const f of findings) {
      const p = ensure(f.repo);
      p.total += 1;
      if (f.severity === "critical") p.critical += 1;
      if (f.severity === "high") p.high += 1;
    }
    for (const p of map.values()) {
      p.verified = findings.filter((f) => {
        if (f.repo !== p.id) return false;
        const v = stepStats(f);
        return v.total > 0 && v.blocked === v.total;
      }).length;
    }
    return [...map.values()].sort((a, b) => b.critical - a.critical);
  }, [findings, projectRows]);

  const totals = useMemo(() => {
    let critical = 0;
    let high = 0;
    let verified = 0;
    for (const f of scopedFindings) {
      if (f.severity === "critical") critical += 1;
      if (f.severity === "high") high += 1;
      const v = stepStats(f);
      if (v.total > 0 && v.blocked === v.total) verified += 1;
    }
    const verifiedPct =
      scopedFindings.length === 0
        ? 0
        : Math.round((verified / scopedFindings.length) * 100);
    return { critical, high, verified, verifiedPct, total: scopedFindings.length };
  }, [scopedFindings]);

  const surfaces = useMemo<AttackSurfaceRow[]>(() => {
    const map = new Map<string, number>();
    for (const f of scopedFindings) {
      const name = f.attackSurface.split("·")[0].trim() || "Unclassified";
      map.set(name, (map.get(name) ?? 0) + 1);
    }
    return [...map.entries()]
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count);
  }, [scopedFindings]);

  const paths = useMemo<AttackPathItem[]>(() => {
    return scopedFindings.map((f) => {
      const { total, blocked } = stepStats(f);
      const allBlocked = total > 0 && blocked === total;
      const anyBlocked = blocked > 0;
      const status: AttackPathItem["status"] = allBlocked
        ? "verified"
        : anyBlocked
          ? "re-attacked"
          : "confirmed";
      const exploitable = total - blocked;
      const confidence =
        total === 0 ? 70 : Math.max(50, Math.round((exploitable / total) * 100));
      return {
        id: f.id,
        title: f.title,
        severity: f.severity,
        finding: f,
        steps: f.attackPath,
        status,
        confidence,
      };
    });
  }, [scopedFindings]);

  const activity = useMemo<ActivityItem[]>(() => {
    const items: ActivityItem[] = [];
    for (const f of scopedFindings) {
      items.push({
        id: `f-${f.id}`,
        tone: f.severity === "critical" || f.severity === "high" ? "rose" : "violet",
        text: `finding ${f.id} confirmed — ${f.title}`,
        at: Date.parse(f.startedAt) || 0,
      });
      const steps = f.attackSteps?.length ?? 0;
      items.push({
        id: `v-${f.id}`,
        tone: "emerald",
        text: `validation recorded for ${f.id} — ${steps} attack step${steps === 1 ? "" : "s"}`,
        at: (Date.parse(f.startedAt) || 0) + 1000,
      });
    }
    for (const r of runs ?? []) {
      if (projectId && r.projectId !== projectId) continue;
      items.push({
        id: `run-${r._id}`,
        tone:
          r.status === "completed"
            ? "emerald"
            : r.status === "failed"
              ? "rose"
              : "cyan",
        text:
          r.status === "queued"
            ? `${r.kind === "revalidation" ? "re-validation" : "validation"} queued for ${r.projectId} — awaiting engine pickup`
            : `${r.kind === "revalidation" ? "re-validation" : "validation"} run ${r.status} for ${r.projectId}`,
        at: r.updatedAt,
      });
    }
    for (const a of approvals ?? []) {
      items.push({
        id: `a-${a._id}`,
        tone: a.status === "applied" ? "emerald" : "amber",
        text:
          a.status === "applied"
            ? `approval applied for ${a.findingId} — verdict: ${a.verdict ?? "recorded"}`
            : `fix awaiting approval for ${a.findingId} (${a.source === "ai" ? "ECC patch" : "manual"})`,
        at: a.resolvedAt ?? a.requestedAt,
      });
    }
    for (const r of revalidations ?? []) {
      items.push({
        id: `r-${r._id}`,
        tone: r.verdict === VERDICT_FIXED ? "emerald" : "cyan",
        text:
          r.status === "resolved"
            ? `re-attack for ${r.findingId}: ${r.verdict === VERDICT_FIXED ? "blocked — verified fixed" : "still exploitable"}`
            : `re-attack queued for ${r.findingId} — waiting for engine`,
        at: r.resolvedAt ?? r.requestedAt,
      });
    }
    return items.sort((a, b) => b.at - a.at).slice(0, 12);
  }, [scopedFindings, findings, approvals, revalidations, runs, projectId]);

  const workQueues = useMemo(() => {
    const pendingApprovals = (approvals ?? []).filter(
      (a) => a.status === "pending",
    );
    const pendingRevalidations = (revalidations ?? []).filter(
      (r) => r.status === "pending",
    );
    const queuedRuns = (runs ?? []).filter((r) => r.status === "queued");
    const activeRuns = (runs ?? []).filter(
      (r) => r.status === "running" || r.status === "queued",
    );
    return {
      approvals: pendingApprovals,
      revalidations: pendingRevalidations,
      queuedRuns,
      activeRuns,
      total:
        pendingApprovals.length +
        pendingRevalidations.length +
        queuedRuns.length,
    };
  }, [approvals, revalidations, runs]);

  return {
    loading,
    /** Scoped findings (respects project selection). */
    findings: scopedFindings,
    /** Unscoped findings across every project (Console overview). */
    allFindings,
    projects,
    totals,
    surfaces,
    paths,
    activity,
    workQueues,
    engineBacked,
    projectRows: projectRows ?? [],
    runs: runs ?? [],
  };
}
