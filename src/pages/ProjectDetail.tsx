import {
  ArrowRight,
  CircleCheck,
  Clock,
  Crosshair,
  FileSearch,
  FlaskConical,
  FolderGit2,
  Play,
  ShieldCheck,
} from "lucide-react";
import { Link, useParams } from "react-router";
import { useMutation } from "convex/react";
import { useState } from "react";
import { toast } from "sonner";
import { api } from "@/convex/_generated/api";
import { PanelShell } from "@/components/panels/PanelShell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { ScrollArea } from "@/components/ui/scroll-area";
import { usePurpleGuardData } from "@/hooks/usePurpleGuardData";
import { cn } from "@/lib/utils";

const SEVERITY_STYLES: Record<string, string> = {
  critical: "border-rose-400/30 bg-rose-400/10 text-rose-300",
  high: "border-amber-400/30 bg-amber-400/10 text-amber-300",
  medium: "border-violet-400/30 bg-violet-400/10 text-violet-300",
  low: "border-white/15 bg-white/[0.05] text-muted-foreground",
};

const SOURCE_META: Record<string, { label: string; className: string }> = {
  github: { label: "GitHub", className: "border-violet-400/25 bg-violet-500/10 text-violet-200" },
  engine: { label: "engine", className: "border-cyan-400/25 bg-cyan-400/10 text-cyan-300" },
  handoff: { label: "handoff", className: "border-amber-400/25 bg-amber-400/10 text-amber-300" },
  manual: { label: "manual", className: "border-white/10 bg-white/[0.03] text-muted-foreground" },
};

const RUN_STATE_STYLES: Record<string, string> = {
  queued: "border-cyan-400/25 bg-cyan-400/10 text-cyan-300",
  running: "border-violet-400/25 bg-violet-500/10 text-violet-200",
  completed: "border-emerald-400/25 bg-emerald-400/10 text-emerald-300",
  failed: "border-rose-400/30 bg-rose-400/10 text-rose-300",
};

export default function ProjectDetail() {
  const { repo = "" } = useParams();
  const decodedRepo = decodeURIComponent(repo);
  const { loading, findings, surfaces, paths, projectRows, runs } =
    usePurpleGuardData(decodedRepo);
  const startRun = useMutation(api.workflow.startRun);
  const [starting, setStarting] = useState(false);
  const [evidencePathId, setEvidencePathId] = useState<string | null>(null);

  const project = projectRows.find((p) => p.repo === decodedRepo);
  const evidencePath = paths.find((p) => p.id === evidencePathId) ?? null;

  // Per-surface status for this project: which attack surfaces have findings,
  // how many, and whether they are verified (all steps blocked).
  const surfaceStatus = surfaces.map((s) => {
    const related = findings.filter(
      (f) => (f.attackSurface.split("·")[0] ?? "").trim() === s.name,
    );
    const verified = related.filter((f) => {
      const steps = f.attackSteps ?? [];
      return steps.length > 0 && steps.every((st) => st.verdict === "blocked");
    }).length;
    return { name: s.name, total: related.length, verified };
  });

  const handleStartValidation = async () => {
    setStarting(true);
    try {
      await startRun({
        projectId: decodedRepo,
        kind: "validation",
        note: "Started from the project detail page",
        scope: { authorizedPaths: ["/**"], blockedPaths: [] },
      });
      toast.success("Validation run queued", {
        description:
          "The engine picks it up via /api/runs/pending, claims it, and posts the outcome.",
      });
    } catch (e) {
      toast.error("Could not queue run", {
        description: e instanceof Error ? e.message : "Unknown error",
      });
    } finally {
      setStarting(false);
    }
  };

  if (!loading && projectRows.length > 0 && !project) {
    return (
      <PanelShell panel="console" badge="Command Center">
        <div className="mx-auto max-w-3xl px-4 py-16 text-center sm:px-6">
          <FolderGit2 className="mx-auto size-8 text-muted-foreground" />
          <h1 className="mt-3 text-lg font-semibold text-foreground">
            Project not found
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            No project with identifier <span className="font-mono">{decodedRepo}</span> is
            registered yet.
          </p>
          <Button asChild className="mt-6 bg-violet-600 text-white hover:bg-violet-500">
            <Link to="/dashboard">Back to Console</Link>
          </Button>
        </div>
      </PanelShell>
    );
  }

  const critical = findings.filter((f) => f.severity === "critical").length;
  const high = findings.filter((f) => f.severity === "high").length;
  const verifiedCount = findings.filter((f) => {
    const steps = f.attackSteps ?? [];
    return steps.length > 0 && steps.every((st) => st.verdict === "blocked");
  }).length;

  return (
    <PanelShell panel="console" badge="Command Center">
      <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
          <div className="min-w-0">
            <Link
              to="/dashboard"
              className="inline-flex items-center gap-1.5 font-mono text-[10px] text-muted-foreground transition-colors hover:text-foreground"
            >
              <ArrowRight className="size-3 rotate-180" />
              Console
            </Link>
            <div className="mt-1.5 flex flex-wrap items-center gap-2.5">
              <h1 className="text-2xl font-semibold tracking-tight text-foreground sm:text-3xl">
                {decodedRepo}
              </h1>
              {project && (
                <Badge
                  variant="outline"
                  className={cn(
                    "font-mono text-[10px]",
                    (SOURCE_META[project.source] ?? SOURCE_META.manual).className,
                  )}
                >
                  {(SOURCE_META[project.source] ?? SOURCE_META.manual).label}
                </Badge>
              )}
            </div>
            <p className="mt-2 max-w-2xl text-sm text-muted-foreground">
              Security state for this project: surfaces, validated attack paths,
              and the workflow runs recorded against it.
            </p>
          </div>
          <Button
            size="sm"
            disabled={starting}
            onClick={() => void handleStartValidation()}
            className="shrink-0 bg-violet-600 text-white shadow-[0_0_24px_rgba(124,58,237,0.4)] hover:bg-violet-500"
          >
            <Play className="size-3.5" />
            {starting ? "Queueing…" : "Start Validation"}
          </Button>
        </div>

        {/* KPIs */}
        <div className="mt-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <StatTile label="Findings" value={String(findings.length)} />
          <StatTile label="Critical" value={String(critical)} tone="text-rose-300" />
          <StatTile label="High" value={String(high)} tone="text-amber-300" />
          <StatTile label="Verified" value={String(verifiedCount)} tone="text-emerald-300" />
        </div>

        {/* Surface status + run history */}
        <div className="mt-6 grid gap-4 lg:grid-cols-2">
          <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-5">
            <h2 className="flex items-center gap-2 text-sm font-medium uppercase tracking-[0.12em] text-muted-foreground">
              <FlaskConical className="size-4 text-violet-300" />
              Attack surfaces
            </h2>
            <ul className="mt-3 space-y-2">
              {surfaceStatus.map((s) => (
                <li
                  key={s.name}
                  className="flex items-center justify-between rounded-lg border border-white/[0.05] bg-white/[0.02] px-3.5 py-2.5"
                >
                  <span className="min-w-0 truncate text-sm text-foreground/90">{s.name}</span>
                  <span className="flex shrink-0 items-center gap-2.5 font-mono text-[11px]">
                    {s.verified > 0 && (
                      <span className="flex items-center gap-1 text-emerald-300">
                        <CircleCheck className="size-3" />
                        {s.verified} verified
                      </span>
                    )}
                    <span className="text-muted-foreground">
                      {s.total} finding{s.total === 1 ? "" : "s"}
                    </span>
                  </span>
                </li>
              ))}
              {surfaceStatus.length === 0 && !loading && (
                <li className="rounded-lg border border-dashed border-white/10 px-3.5 py-6 text-center text-xs text-muted-foreground">
                  No attack surfaces recorded for this project yet.
                </li>
              )}
            </ul>
          </div>

          <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-5">
            <h2 className="flex items-center gap-2 text-sm font-medium uppercase tracking-[0.12em] text-muted-foreground">
              <Clock className="size-4 text-violet-300" />
              Run history
            </h2>
            <ul className="mt-3 space-y-2">
              {runs.map((r) => (
                <li
                  key={r._id}
                  className="flex items-center justify-between gap-3 rounded-lg border border-white/[0.05] bg-white/[0.02] px-3.5 py-2.5"
                >
                  <span className="min-w-0">
                    <span className="block font-mono text-[11px] capitalize text-foreground/90">
                      {r.kind === "revalidation" ? "re-validation" : "validation"} run
                    </span>
                    <span className="block font-mono text-[10px] text-muted-foreground">
                      {new Date(r.createdAt).toLocaleString()}
                      {r.note ? ` · ${r.note}` : ""}
                    </span>
                  </span>
                  <Badge
                    variant="outline"
                    className={cn(
                      "shrink-0 font-mono text-[10px]",
                      RUN_STATE_STYLES[r.status] ?? "",
                    )}
                  >
                    {r.status}
                  </Badge>
                </li>
              ))}
              {runs.length === 0 && !loading && (
                <li className="rounded-lg border border-dashed border-white/10 px-3.5 py-6 text-center text-xs text-muted-foreground">
                  No runs recorded yet — start validation to queue one.
                </li>
              )}
            </ul>
            <p className="mt-3 font-mono text-[10px] text-muted-foreground">
              Queued runs are real executable work: the engine polls
              /api/runs/pending and claims them with the run's scope attached.
            </p>
          </div>
        </div>

        {/* Attack paths */}
        <div className="mt-6">
          <div className="flex items-center justify-between">
            <h2 className="flex items-center gap-2 text-sm font-medium uppercase tracking-[0.12em] text-muted-foreground">
              <Crosshair className="size-4 text-violet-300" />
              Validated attack paths
            </h2>
            <Link
              to={`/hacker?project=${encodeURIComponent(decodedRepo)}`}
              className="inline-flex items-center gap-1.5 font-mono text-[10px] text-violet-300 hover:text-violet-200"
            >
              Open in Hacker panel
              <ArrowRight className="size-3" />
            </Link>
          </div>
          <div className="mt-3 space-y-3">
            {paths.map((p) => (
              <div
                key={p.id}
                className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4 transition-colors hover:border-violet-400/20"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-[11px] text-muted-foreground">
                      PATH-{p.id}
                    </span>
                    <Badge
                      variant="outline"
                      className={cn("font-mono text-[10px] uppercase tracking-wider", SEVERITY_STYLES[p.severity] ?? "")}
                    >
                      {p.severity}
                    </Badge>
                  </div>
                  <button
                    type="button"
                    onClick={() => setEvidencePathId(p.id)}
                    className="inline-flex items-center gap-1.5 font-mono text-[10px] text-violet-300 hover:text-violet-200"
                  >
                    <FileSearch className="size-3" />
                    View evidence
                  </button>
                </div>
                <h3 className="mt-1.5 text-sm font-semibold text-foreground">{p.title}</h3>
                <ol className="mt-2 space-y-1 border-l border-white/[0.08] pl-4">
                  {p.steps.slice(0, 3).map((step, i) => (
                    <li key={i} className="font-mono text-[11px] text-muted-foreground">
                      {step}
                    </li>
                  ))}
                  {p.steps.length > 3 && (
                    <li className="font-mono text-[10px] text-muted-foreground">
                      +{p.steps.length - 3} more steps…
                    </li>
                  )}
                </ol>
              </div>
            ))}
            {paths.length === 0 && !loading && (
              <div className="rounded-xl border border-dashed border-white/10 p-8 text-center text-sm text-muted-foreground">
                No validated attack paths for this project yet.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Evidence dialog (reuse of the Hacker panel's evidence contract) */}
      <Dialog
        open={evidencePath !== null}
        onOpenChange={(open) => !open && setEvidencePathId(null)}
      >
        <DialogContent className="max-w-2xl border-white/10 bg-[oklch(0.16_0.012_288)]">
          {evidencePath && (
            <>
              <DialogHeader>
                <DialogTitle className="flex items-center gap-2 text-base">
                  <ShieldCheck className="size-4 text-violet-300" />
                  Evidence · PATH-{evidencePath.id}
                </DialogTitle>
                <DialogDescription>
                  Recorded by the validator during the authorized run — nothing simulated.
                </DialogDescription>
              </DialogHeader>
              <ScrollArea className="max-h-[55vh] pr-2">
                <div className="space-y-3">
                  {evidencePath.finding.evidence.map((ev) => (
                    <div key={ev.id} className="rounded-lg border border-white/[0.06] bg-black/30">
                      <div className="flex items-center justify-between border-b border-white/[0.06] px-3.5 py-2">
                        <span className="font-mono text-[11px] text-foreground/90">{ev.label}</span>
                        <Badge
                          variant="outline"
                          className="font-mono text-[9px] uppercase text-muted-foreground"
                        >
                          {ev.kind}
                        </Badge>
                      </div>
                      <pre className="max-h-52 overflow-auto p-3 font-mono text-[10.5px] leading-relaxed text-foreground/85">
                        {ev.content}
                      </pre>
                    </div>
                  ))}
                  {evidencePath.finding.evidence.length === 0 && (
                    <p className="py-6 text-center text-sm text-muted-foreground">
                      No evidence items recorded for this finding.
                    </p>
                  )}
                </div>
              </ScrollArea>
              <DialogFooter>
                <Button variant="outline" onClick={() => setEvidencePathId(null)}>
                  Close
                </Button>
              </DialogFooter>
            </>
          )}
        </DialogContent>
      </Dialog>
    </PanelShell>
  );
}

function StatTile({
  label,
  value,
  tone,
}: {
  label: string;
  value: string;
  tone?: string;
}) {
  return (
    <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4">
      <p className="text-[11px] font-medium uppercase tracking-[0.12em] text-muted-foreground">
        {label}
      </p>
      <p className={cn("mt-1 font-mono text-xl font-semibold tracking-tight", tone ?? "text-foreground")}>
        {value}
      </p>
    </div>
  );
}
