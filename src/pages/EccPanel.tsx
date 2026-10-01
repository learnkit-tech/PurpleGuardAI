import {
  Activity,
  CircleCheck,
  Clock,
  Cpu,
  GitBranch,
  ShieldCheck,
  Workflow,
} from "lucide-react";
import { Link } from "react-router";
import { PanelShell } from "@/components/panels/PanelShell";
import { Badge } from "@/components/ui/badge";
import { usePurpleGuardData } from "@/hooks/usePurpleGuardData";
import { cn } from "@/lib/utils";

export default function EccPanel() {
  const { findings, totals, workQueues, activity, engineBacked } =
    usePurpleGuardData();

  const pipeline = [
    {
      id: "validate",
      label: "Validate",
      desc: "Authorized attacks executed by the validator",
      count: findings.length,
      done: findings.length > 0,
    },
    {
      id: "fix",
      label: "Fix",
      desc: "Approved buffers awaiting engine apply + re-attack",
      count: workQueues.approvals.length,
      done: workQueues.approvals.length === 0,
    },
    {
      id: "verify",
      label: "Verify",
      desc: "Fresh re-attacks queued with the engine",
      count: workQueues.revalidations.length,
      done: workQueues.revalidations.length === 0,
    },
  ];

  return (
    <PanelShell panel="ecc" badge="Enterprise Cyber Command">
      <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
          <div>
            <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted-foreground">
              ecc control center
            </p>
            <h1 className="mt-1 text-2xl font-semibold tracking-tight text-foreground sm:text-3xl">
              What is PurpleGuard's machinery doing?
            </h1>
            <p className="mt-2 max-w-2xl text-sm text-muted-foreground">
              ECC is the orchestration layer under Hacker, Developer, and the
              Console. This panel reflects only real work queues and recorded
              results — no invented agents.
            </p>
          </div>
          <span
            className={cn(
              "inline-flex w-fit items-center gap-1.5 rounded-full border px-3 py-1.5 font-mono text-[10px] font-medium uppercase tracking-wider",
              engineBacked
                ? "border-emerald-400/25 bg-emerald-400/10 text-emerald-300"
                : "border-amber-400/25 bg-amber-400/10 text-amber-300",
            )}
          >
            <span
              className={cn(
                "size-1.5 rounded-full",
                engineBacked ? "animate-pulse bg-emerald-400" : "bg-amber-400",
              )}
            />
            {engineBacked ? "Engine connected" : "Seed data — import engine output"}
          </span>
        </div>

        {/* Pipeline */}
        <div className="mt-6 grid gap-4 md:grid-cols-3">
          {pipeline.map((stage, i) => (
            <div
              key={stage.id}
              className="relative rounded-xl border border-white/[0.06] bg-white/[0.02] p-5"
            >
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.14em] text-muted-foreground">
                  <Workflow className="size-3.5 text-violet-300" />
                  stage {i + 1} · {stage.label}
                </span>
                <Badge
                  variant="outline"
                  className={cn(
                    "font-mono text-[10px]",
                    stage.count === 0
                      ? "border-white/10 bg-white/[0.03] text-muted-foreground"
                      : "border-amber-400/25 bg-amber-400/10 text-amber-300",
                  )}
                >
                  {stage.count === 0
                    ? "clear"
                    : `${stage.count} queued`}
                </Badge>
              </div>
              <p className="mt-3 text-sm font-medium text-foreground">
                {stage.desc}
              </p>
            </div>
          ))}
        </div>

        {/* Work queues + totals */}
        <div className="mt-6 grid gap-4 lg:grid-cols-3">
          {/* Approvals queue */}
          <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-5 lg:col-span-2">
            <div className="flex items-center justify-between">
              <h2 className="flex items-center gap-2 text-sm font-medium uppercase tracking-[0.12em] text-muted-foreground">
                <GitBranch className="size-4 text-violet-300" />
                Approvals queue
              </h2>
              <span className="font-mono text-[10px] text-muted-foreground">
                engine polls /api/approvals/pending
              </span>
            </div>
            <ul className="mt-3 space-y-2">
              {workQueues.approvals.map((a) => (
                <li
                  key={a._id}
                  className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-amber-400/20 bg-amber-400/[0.04] px-3.5 py-2.5"
                >
                  <span className="flex min-w-0 items-center gap-2.5 font-mono text-[11px]">
                    <Clock className="size-3.5 shrink-0 text-amber-300" />
                    <span className="text-foreground/90">{a.findingId}</span>
                    <span className="text-muted-foreground">
                      {a.source === "ai" ? "ECC patch" : "manual buffer"}
                    </span>
                  </span>
                  <Badge
                    variant="outline"
                    className="border-amber-400/25 bg-amber-400/10 font-mono text-[10px] text-amber-300"
                  >
                    awaiting engine
                  </Badge>
                </li>
              ))}
              {workQueues.approvals.length === 0 && (
                <li className="rounded-lg border border-white/[0.05] bg-white/[0.01] px-3.5 py-3 text-sm text-muted-foreground">
                  Nothing pending — approved buffers have been applied and
                  re-attacked.
                </li>
              )}
            </ul>

            <div className="mt-5 flex items-center justify-between">
              <h2 className="flex items-center gap-2 text-sm font-medium uppercase tracking-[0.12em] text-muted-foreground">
                <Activity className="size-4 text-cyan-300" />
                Revalidation queue
              </h2>
              <span className="font-mono text-[10px] text-muted-foreground">
                engine polls /api/revalidate/pending
              </span>
            </div>
            <ul className="mt-3 space-y-2">
              {workQueues.revalidations.map((r) => (
                <li
                  key={r._id}
                  className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-cyan-400/20 bg-cyan-400/[0.04] px-3.5 py-2.5"
                >
                  <span className="flex min-w-0 items-center gap-2.5 font-mono text-[11px]">
                    <Clock className="size-3.5 shrink-0 text-cyan-300" />
                    <span className="text-foreground/90">{r.findingId}</span>
                    <span className="text-muted-foreground">fresh re-attack</span>
                  </span>
                  <Badge
                    variant="outline"
                    className="border-cyan-400/25 bg-cyan-400/10 font-mono text-[10px] text-cyan-300"
                  >
                    waiting for engine
                  </Badge>
                </li>
              ))}
              {workQueues.revalidations.length === 0 && (
                <li className="rounded-lg border border-white/[0.05] bg-white/[0.01] px-3.5 py-3 text-sm text-muted-foreground">
                  No re-attacks queued. Trigger one from a finding's
                  "Re-run validation".
                </li>
              )}
            </ul>
          </div>

          {/* System totals */}
          <div className="space-y-4">
            <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-5">
              <h2 className="flex items-center gap-2 text-sm font-medium uppercase tracking-[0.12em] text-muted-foreground">
                <Cpu className="size-4 text-violet-300" />
                Recorded state
              </h2>
              <dl className="mt-3 space-y-2 font-mono text-[11px]">
                <Row label="findings stored" value={String(totals.total)} />
                <Row label="attack steps recorded" value={String(findings.reduce((n, f) => n + (f.attackSteps?.length ?? 0), 0))} />
                <Row label="steps blocked" value={String(findings.reduce((n, f) => n + (f.attackSteps ?? []).filter((s) => s.verdict === "blocked").length, 0))} />
                <Row label="verified fixed" value={String(totals.verified)} />
              </dl>
            </div>

            <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-5">
              <h2 className="text-sm font-medium uppercase tracking-[0.12em] text-muted-foreground">
                Agent fleet
              </h2>
              <p className="mt-2 text-xs leading-relaxed text-muted-foreground">
                Agent telemetry appears here when ECC's orchestration is wired
                to live agents. Until then this panel deliberately shows no
                fake fleet — the real queues above are the ground truth.
              </p>
              <Link
                to="/developer"
                className="mt-3 inline-flex items-center gap-1.5 font-mono text-[10px] text-violet-300 hover:text-violet-200"
              >
                Open Developer Workspace
                <ShieldCheck className="size-3" />
              </Link>
            </div>
          </div>
        </div>

        {/* Execution log */}
        <div className="mt-6 rounded-xl border border-white/[0.06] bg-white/[0.02] p-5">
          <div className="flex items-center justify-between">
            <h2 className="flex items-center gap-2 text-sm font-medium uppercase tracking-[0.12em] text-muted-foreground">
              <CircleCheck className="size-4 text-emerald-300" />
              Executions & results
            </h2>
            <span className="font-mono text-[10px] text-muted-foreground">
              approvals + revalidations, newest first
            </span>
          </div>
          <ul className="mt-3 space-y-1">
            {activity
              .filter((a) => a.id.startsWith("a-") || a.id.startsWith("r-"))
              .map((a) => (
                <li
                  key={a.id}
                  className="flex items-center gap-2.5 rounded-lg px-2 py-2 font-mono text-[11px] transition-colors hover:bg-white/[0.02]"
                >
                  <span
                    className={cn(
                      "size-1.5 shrink-0 rounded-full",
                      a.tone === "emerald" && "bg-emerald-400",
                      a.tone === "amber" && "bg-amber-400",
                      a.tone === "cyan" && "bg-cyan-400",
                      a.tone === "rose" && "bg-rose-400",
                      a.tone === "violet" && "bg-violet-400",
                    )}
                  />
                  <span className="min-w-0 flex-1 truncate text-foreground/85">
                    {a.text}
                  </span>
                </li>
              ))}
            {activity.filter((a) => a.id.startsWith("a-") || a.id.startsWith("r-"))
              .length === 0 && (
              <li className="px-2 py-4 text-sm text-muted-foreground">
                No executions yet. Approve a fix or re-run validation on a
                finding to see results here.
              </li>
            )}
          </ul>
        </div>
      </div>
    </PanelShell>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-baseline justify-between gap-3">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="text-foreground">{value}</dd>
    </div>
  );
}
