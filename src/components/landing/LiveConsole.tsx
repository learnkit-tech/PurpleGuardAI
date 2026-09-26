import { AnimatePresence, motion } from "framer-motion";
import {
  CloudCog,
  Database,
  GitBranch,
  ShieldAlert,
  Sparkles,
  TriangleAlert,
} from "lucide-react";
import { useMemo } from "react";
import { cn } from "@/lib/utils";
import { Reveal } from "./Reveal";
import { SectionHeader } from "./SectionHeader";
import { ScoreRing, StatusDot, useTicker } from "./console";
import {
  AGENT_ACTIVITY,
  AI_RECOMMENDATIONS,
  HEATMAP_CELLS,
  RECENT_SCANS,
  heatmapIntensity,
} from "./data";

function KpiCard({
  icon,
  label,
  value,
  delta,
  deltaTone = "emerald",
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  delta?: string;
  deltaTone?: "emerald" | "rose";
}) {
  return (
    <div className="flex items-center gap-3.5 rounded-xl border border-white/[0.06] bg-white/[0.02] p-4">
      <span className="flex size-9 shrink-0 items-center justify-center rounded-lg border border-white/10 bg-white/[0.03] text-violet-300">
        {icon}
      </span>
      <div className="min-w-0">
        <p className="truncate text-[11px] font-medium uppercase tracking-[0.12em] text-muted-foreground">
          {label}
        </p>
        <div className="flex items-baseline gap-2">
          <p className="font-mono text-xl font-semibold tracking-tight text-foreground">
            {value}
          </p>
          {delta && (
            <span
              className={cn(
                "font-mono text-[11px]",
                deltaTone === "emerald" ? "text-emerald-400" : "text-rose-400",
              )}
            >
              {delta}
            </span>
          )}
        </div>
      </div>
    </div>
  );
}

function RiskHeatmap() {
  const cells = useMemo(
    () => Array.from({ length: HEATMAP_CELLS }, (_, i) => heatmapIntensity(i)),
    [],
  );

  return (
    <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4">
      <div className="mb-3 flex items-center justify-between">
        <h3 className="text-xs font-medium uppercase tracking-[0.12em] text-muted-foreground">
          Risk Heatmap
        </h3>
        <span className="font-mono text-[10px] text-muted-foreground">
          last 24h · prod + staging
        </span>
      </div>
      <div className="grid grid-cols-12 gap-1">
        {cells.map((level, i) => (
          <span
            key={i}
            className={cn(
              "aspect-square rounded-[3px] transition-colors duration-300",
              level === 0 && "bg-white/[0.03]",
              level === 1 && "bg-violet-500/20 hover:bg-violet-400/40",
              level === 2 && "bg-violet-500/45 hover:bg-violet-400/60",
              level === 3 &&
                "bg-violet-400/80 shadow-[0_0_10px_rgba(167,139,250,0.5)] hover:bg-violet-300",
            )}
          />
        ))}
      </div>
      <div className="mt-3 flex items-center justify-between font-mono text-[10px] text-muted-foreground">
        <span>low</span>
        <div className="flex items-center gap-1.5">
          {[0, 1, 2, 3].map((l) => (
            <span
              key={l}
              className={cn(
                "size-2 rounded-[2px]",
                l === 0 && "bg-white/[0.08]",
                l === 1 && "bg-violet-500/20",
                l === 2 && "bg-violet-500/45",
                l === 3 && "bg-violet-400/80",
              )}
            />
          ))}
          <span>critical</span>
        </div>
      </div>
    </div>
  );
}

function AgentActivity() {
  const tick = useTicker(AGENT_ACTIVITY.length, 2200);
  const active = AGENT_ACTIVITY[tick];

  return (
    <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4">
      <div className="mb-3 flex items-center justify-between">
        <h3 className="text-xs font-medium uppercase tracking-[0.12em] text-muted-foreground">
          Agent Activity
        </h3>
        <span className="inline-flex items-center gap-1.5 font-mono text-[10px] text-emerald-300">
          <span className="size-1.5 animate-pulse rounded-full bg-emerald-400" />
          {AGENT_ACTIVITY.length} active
        </span>
      </div>
      <ul className="space-y-1.5">
        {AGENT_ACTIVITY.map((agent) => (
          <li
            key={agent.agent}
            className={cn(
              "flex items-center justify-between gap-2 rounded-lg px-2.5 py-2 font-mono text-[11px] transition-colors",
              agent.agent === active.agent
                ? "bg-violet-500/10 text-foreground"
                : "text-muted-foreground",
            )}
          >
            <span className="flex min-w-0 items-center gap-2">
              <StatusDot tone={agent.tone} />
              <span className="truncate text-violet-200/90">{agent.agent}</span>
              <span className="hidden truncate text-white/35 sm:inline">
                · {agent.role}
              </span>
            </span>
            <AnimatePresence mode="wait">
              {agent.agent === active.agent && (
                <motion.span
                  key={active.status}
                  initial={{ opacity: 0, y: 4 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -4 }}
                  transition={{ duration: 0.25 }}
                  className="truncate text-emerald-300/90"
                >
                  {agent.status}
                </motion.span>
              )}
            </AnimatePresence>
          </li>
        ))}
      </ul>
    </div>
  );
}

function AiRecommendations() {
  const tick = useTicker(AI_RECOMMENDATIONS.length, 3600);
  const recommendation = AI_RECOMMENDATIONS[tick];

  return (
    <div className="flex flex-col rounded-xl border border-white/[0.06] bg-white/[0.02] p-4">
      <div className="mb-3 flex items-center justify-between">
        <h3 className="text-xs font-medium uppercase tracking-[0.12em] text-muted-foreground">
          AI Recommendations
        </h3>
        <Sparkles className="size-3.5 text-violet-300" />
      </div>
      <div className="flex flex-1 items-start gap-2.5 rounded-lg border border-violet-400/20 bg-violet-500/[0.07] p-3.5">
        <TriangleAlert className="mt-0.5 size-4 shrink-0 text-violet-300" />
        <AnimatePresence mode="wait">
          <motion.p
            key={recommendation}
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -6 }}
            transition={{ duration: 0.3 }}
            className="text-sm leading-relaxed text-violet-100/90"
          >
            {recommendation}
          </motion.p>
        </AnimatePresence>
      </div>
      <p className="mt-3 font-mono text-[10px] text-muted-foreground">
        Next rec in {tick + 1}/{AI_RECOMMENDATIONS.length} · ranked by exploitability
      </p>
    </div>
  );
}

function RecentScans() {
  return (
    <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4">
      <div className="mb-3 flex items-center justify-between">
        <h3 className="text-xs font-medium uppercase tracking-[0.12em] text-muted-foreground">
          Recent Scans
        </h3>
        <span className="font-mono text-[10px] text-muted-foreground">
          312 repos · 6 pipelines
        </span>
      </div>
      <ul className="divide-y divide-white/[0.05]">
        {RECENT_SCANS.map((scan) => (
          <li
            key={scan.repo}
            className="flex items-center justify-between gap-3 py-2.5 font-mono text-[11px]"
          >
            <span className="flex min-w-0 items-center gap-2.5">
              <GitBranch className="size-3.5 shrink-0 text-white/35" />
              <span className="truncate text-foreground/90">{scan.repo}</span>
            </span>
            <span className="flex shrink-0 items-center gap-3">
              <span
                className={cn(
                  "inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[10px]",
                  scan.statusTone === "emerald" &&
                    "border-emerald-400/25 bg-emerald-400/10 text-emerald-300",
                  scan.statusTone === "amber" &&
                    "border-amber-400/25 bg-amber-400/10 text-amber-300",
                  scan.statusTone === "violet" &&
                    "border-violet-400/25 bg-violet-400/10 text-violet-300",
                  scan.statusTone === "cyan" &&
                    "border-cyan-400/25 bg-cyan-400/10 text-cyan-300",
                )}
              >
                {scan.status}
              </span>
              <span className="hidden w-10 text-right text-muted-foreground sm:inline">
                {scan.findings} fx
              </span>
              <span className="hidden w-10 text-right text-white/30 md:inline">
                {scan.duration}
              </span>
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function LiveConsole() {
  return (
    <section id="preview" className="relative overflow-hidden py-24 sm:py-32">
      <div aria-hidden="true" className="absolute inset-0">
        <div className="absolute left-1/2 top-0 h-[360px] w-[720px] -translate-x-1/2 rounded-full bg-violet-600/15 blur-[130px]" />
      </div>

      <div className="relative mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <SectionHeader
          eyebrow="Live Preview"
          title="The command center, in action"
          description="A realistic view of the ECC console. Every metric below is live in the product — score, posture, agents, and autonomous fixes updating in real time."
        />

        <Reveal delay={0.12} className="mt-14">
          <div className="relative">
            <div
              aria-hidden="true"
              className="absolute -inset-4 rounded-[2rem] bg-gradient-to-br from-violet-600/15 via-transparent to-cyan-400/10 blur-2xl"
            />
            <div className="relative overflow-hidden rounded-2xl border border-white/10 bg-[#0b0a13]/95 shadow-2xl shadow-violet-950/40 backdrop-blur-xl">
              {/* Chrome */}
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.07] px-4 py-3 sm:px-5">
                <div className="flex items-center gap-1.5">
                  <span className="size-2.5 rounded-full bg-white/15" />
                  <span className="size-2.5 rounded-full bg-white/15" />
                  <span className="size-2.5 rounded-full bg-white/15" />
                </div>
                <div className="hidden items-center gap-1 sm:flex">
                  {["Overview", "Threats", "Agents", "Compliance"].map(
                    (tab, i) => (
                      <span
                        key={tab}
                        className={cn(
                          "rounded-md px-3 py-1 font-mono text-[11px] transition-colors",
                          i === 0
                            ? "bg-white/[0.06] text-foreground"
                            : "text-muted-foreground hover:text-foreground",
                        )}
                      >
                        {tab}
                      </span>
                    ),
                  )}
                </div>
                <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-400/25 bg-emerald-400/10 px-2.5 py-0.5 font-mono text-[10px] font-medium uppercase tracking-wider text-emerald-300">
                  <span className="size-1.5 animate-pulse rounded-full bg-emerald-400" />
                  Live · 3 regions
                </span>
              </div>

              {/* Body */}
              <div className="space-y-4 p-4 sm:p-5">
                {/* KPIs */}
                <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                  <div className="flex items-center justify-center gap-4 rounded-xl border border-white/[0.06] bg-white/[0.02] p-4 lg:col-span-1">
                    <ScoreRing score={92} size={96} strokeWidth={7} />
                  </div>
                  <KpiCard
                    icon={<ShieldAlert className="size-4" />}
                    label="Detected Vulnerabilities"
                    value="247"
                    delta="38 resolved today"
                  />
                  <KpiCard
                    icon={<CloudCog className="size-4" />}
                    label="Cloud Assets"
                    value="1,284"
                    delta="3 regions"
                  />
                  <KpiCard
                    icon={<Database className="size-4" />}
                    label="Repositories"
                    value="312"
                    delta="6 pipelines"
                  />
                </div>

                {/* Middle row */}
                <div className="grid gap-3 lg:grid-cols-3">
                  <RiskHeatmap />
                  <AgentActivity />
                  <AiRecommendations />
                </div>

                {/* Scans */}
                <RecentScans />
              </div>
            </div>
          </div>
        </Reveal>
      </div>
    </section>
  );
}
