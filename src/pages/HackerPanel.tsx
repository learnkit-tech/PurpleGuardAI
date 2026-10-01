import {
  Crosshair,
  FileSearch,
  FlaskConical,
  Play,
  Send,
  ShieldCheck,
  ShieldOff,
  Clock3,
} from "lucide-react";
import { useState } from "react";
import { useMutation } from "convex/react";
import { toast } from "sonner";
import { api } from "@/convex/_generated/api";
import type { EngineFinding } from "@/components/developer/ingest";
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
import { Textarea } from "@/components/ui/textarea";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/ui/tabs";
import {
  usePurpleGuardData,
  type AttackPathItem,
} from "@/hooks/usePurpleGuardData";
import { useProjectSelection } from "@/hooks/useProjectSelection";
import { cn } from "@/lib/utils";

const SEVERITY_STYLES: Record<string, string> = {
  critical: "border-rose-400/30 bg-rose-400/10 text-rose-300",
  high: "border-amber-400/30 bg-amber-400/10 text-amber-300",
  medium: "border-violet-400/30 bg-violet-400/10 text-violet-300",
  low: "border-white/15 bg-white/[0.05] text-muted-foreground",
};

function toOrchestratorJson(f: EngineFinding): unknown {
  return {
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
    run: { run_id: f.runId, started_at: f.startedAt },
  };
}

function AttackPathCard({
  path,
  sent,
  sending,
  onEvidence,
  onSend,
}: {
  path: AttackPathItem;
  sent: boolean;
  sending: boolean;
  onEvidence: () => void;
  onSend: () => void;
}) {
  return (
    <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4 transition-colors hover:border-violet-400/20">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-[11px] text-muted-foreground">
              PATH-{path.id}
            </span>
            <Badge
              variant="outline"
              className={cn(
                "font-mono text-[10px] uppercase tracking-wider",
                SEVERITY_STYLES[path.severity] ?? "",
              )}
            >
              {path.severity}
            </Badge>
            <Badge
              variant="outline"
              className={cn(
                "font-mono text-[10px]",
                path.status === "verified"
                  ? "border-emerald-400/25 bg-emerald-400/10 text-emerald-300"
                  : path.status === "re-attacked"
                    ? "border-cyan-400/25 bg-cyan-400/10 text-cyan-300"
                    : "border-amber-400/25 bg-amber-400/10 text-amber-300",
              )}
            >
              {path.status === "verified"
                ? "VERIFIED BLOCKED"
                : path.status === "re-attacked"
                  ? "RE-ATTACKED"
                  : "CONFIRMED"}
            </Badge>
          </div>
          <h3 className="mt-1.5 text-sm font-semibold tracking-tight text-foreground">
            {path.title}
          </h3>
        </div>
        <span className="shrink-0 text-right font-mono text-[10px] text-muted-foreground">
          {path.finding.repo}
          <br />
          confidence {path.confidence}%
        </span>
      </div>

      {/* Attack chain */}
      <ol className="mt-3 space-y-1.5 border-l border-white/[0.08] pl-4">
        {path.steps.map((step, i) => (
          <li
            key={i}
            className="relative font-mono text-[11px] text-muted-foreground"
          >
            <span
              className={cn(
                "absolute -left-[21px] top-1.5 size-1.5 rounded-full",
                i === 0 ? "bg-violet-400" : "bg-white/25",
              )}
            />
            {step}
          </li>
        ))}
      </ol>

      <div className="mt-3 flex flex-wrap items-center gap-2">
        <Button variant="outline" size="sm" onClick={onEvidence}>
          <FileSearch className="size-3.5" />
          View Evidence
        </Button>
        <Button
          size="sm"
          onClick={onSend}
          disabled={sent || sending}
          className="bg-violet-600 text-white hover:bg-violet-500"
        >
          <Send className="size-3.5" />
          {sent ? "Sent to Developer" : "Send to Developer"}
        </Button>
      </div>
    </div>
  );
}

export default function HackerPanel() {
  const { projectId } = useProjectSelection();
  const { loading, findings, surfaces, paths, runs } =
    usePurpleGuardData(projectId ?? undefined);
  const upsert = useMutation(api.findings.upsertFromUi);
  const startRun = useMutation(api.workflow.startRun);
  const [evidencePath, setEvidencePath] = useState<AttackPathItem | null>(null);
  const [sentIds, setSentIds] = useState<Set<string>>(new Set());
  const [sending, setSending] = useState(false);
  const [startingRun, setStartingRun] = useState(false);
  const [scopeOpen, setScopeOpen] = useState(false);
  const [scopeAuthorized, setScopeAuthorized] = useState("");
  const [scopeBlocked, setScopeBlocked] = useState("");

  /** One entry per line; trim; drop empties. Empty authorized = "/**" (full). */
  const parseScope = (authorized: string, blocked: string) => {
    const authorizedPaths = authorized
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean);
    const blockedPaths = blocked
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean);
    return {
      authorizedPaths: authorizedPaths.length > 0 ? authorizedPaths : ["/**"],
      blockedPaths: blockedPaths.length > 0 ? blockedPaths : undefined,
    };
  };

  const handleStartValidation = async () => {
    const target = projectId ?? findings[0]?.repo ?? "";
    if (!target) return;
    setStartingRun(true);
    try {
      await startRun({
        projectId: target,
        kind: "validation",
        note: "Started from the Hacker panel",
        scope: parseScope(scopeAuthorized, scopeBlocked),
      });
      toast.success("Validation run queued", {
        description:
          "The engine will pick it up via /api/runs/pending, claim it, and post the outcome.",
      });
      setScopeOpen(false);
    } catch (e) {
      toast.error("Could not queue run", {
        description: e instanceof Error ? e.message : "Unknown error",
      });
    } finally {
      setStartingRun(false);
    }
  };

  const handleSend = async (path: AttackPathItem) => {
    setSending(true);
    try {
      await upsert({ payload: toOrchestratorJson(path.finding) });
      setSentIds((prev) => new Set(prev).add(path.id));
      toast.success(`Finding ${path.id} sent to the Developer Workspace`, {
        description: "It now appears in the developer's findings list.",
      });
    } catch (e) {
      toast.error("Handoff failed", {
        description:
          e instanceof Error ? e.message : "Could not persist the finding.",
      });
    } finally {
      setSending(false);
    }
  };

  const filesAnalyzed = findings.reduce(
    (n, f) => n + (f.vulnerableCode ? f.vulnerableCode.split("\n").length : 0),
    0,
  );

  return (
    <PanelShell panel="hacker" badge="Security Validation">
      <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        {/* Overview */}
        <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
          <div>
            <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted-foreground">
              authorized security validation
            </p>
            <h1 className="mt-1 text-2xl font-semibold tracking-tight text-foreground sm:text-3xl">
              How can this application actually be attacked?
            </h1>
            <p className="mt-2 max-w-2xl text-sm text-muted-foreground">
              The Hacker side attempts authorized validation, proves whether an
              apparent weakness is really exploitable, and records the evidence —
              then hands it to the developer.
            </p>
          </div>
          <Button
            size="sm"
            disabled={startingRun || (projectId === null && findings.length === 0)}
            className="bg-violet-600 text-white shadow-[0_0_24px_rgba(124,58,237,0.4)] hover:bg-violet-500"
            onClick={() => setScopeOpen(true)}
          >
            <Play className="size-3.5" />
            {startingRun ? "Queueing…" : "Start Validation"}
          </Button>
        </div>

        {/* Stats */}
        <div className="mt-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <StatTile label="Files analyzed" value={String(filesAnalyzed)} />
          <StatTile label="Attack surfaces" value={String(surfaces.length)} />
          <StatTile label="Attack paths" value={String(paths.length)} />
          <StatTile
            label="Validated findings"
            value={String(
              findings.filter((f) => (f.attackSteps?.length ?? 0) > 0).length,
            )}
          />
        </div>

        <Tabs defaultValue="paths" className="mt-8 space-y-4">
          <TabsList className="bg-white/[0.03]">
            <TabsTrigger value="paths" className="gap-1.5">
              <Crosshair className="size-3.5" />
              Attack paths
            </TabsTrigger>
            <TabsTrigger value="surfaces" className="gap-1.5">
              <FlaskConical className="size-3.5" />
              Attack surfaces
            </TabsTrigger>
            <TabsTrigger value="runs" className="gap-1.5">
              <Clock3 className="size-3.5" />
              Runs
            </TabsTrigger>
          </TabsList>

          <TabsContent value="paths" className="mt-0 space-y-3">
            {paths.map((p) => (
              <AttackPathCard
                key={p.id}
                path={p}
                sent={sentIds.has(p.id)}
                sending={sending}
                onEvidence={() => setEvidencePath(p)}
                onSend={() => void handleSend(p)}
              />
            ))}
            {paths.length === 0 && !loading && (
              <p className="rounded-xl border border-dashed border-white/10 p-8 text-center text-sm text-muted-foreground">
                No attack paths recorded yet.
              </p>
            )}
          </TabsContent>

          <TabsContent value="surfaces" className="mt-0">
            <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-5">
              <h2 className="text-sm font-medium uppercase tracking-[0.12em] text-muted-foreground">
                Attack surfaces
              </h2>
              <ul className="mt-3 space-y-2">
                {surfaces.map((s) => (
                  <li
                    key={s.name}
                    className="flex items-center justify-between rounded-lg border border-white/[0.05] bg-white/[0.02] px-3.5 py-2.5"
                  >
                    <span className="text-sm text-foreground/90">{s.name}</span>
                    <span className="font-mono text-[11px] text-muted-foreground">
                      {s.count} path{s.count === 1 ? "" : "s"}
                    </span>
                  </li>
                ))}
              </ul>
              <p className="mt-3 font-mono text-[10px] text-muted-foreground">
                Derived from validated findings · nothing is simulated
              </p>
            </div>
          </TabsContent>

          <TabsContent value="runs" className="mt-0 space-y-3">
            {runs.map((r) => (
              <div
                key={r._id}
                className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-[11px] capitalize text-foreground/90">
                      {r.kind === "revalidation" ? "re-validation" : "validation"} · {r.projectId}
                    </span>
                    <Badge
                      variant="outline"
                      className={cn(
                        "font-mono text-[10px]",
                        r.status === "completed"
                          ? "border-emerald-400/25 bg-emerald-400/10 text-emerald-300"
                          : r.status === "failed"
                            ? "border-rose-400/30 bg-rose-400/10 text-rose-300"
                            : r.status === "running"
                              ? "border-violet-400/25 bg-violet-500/10 text-violet-200"
                              : "border-cyan-400/25 bg-cyan-400/10 text-cyan-300",
                      )}
                    >
                      {r.status}
                    </Badge>
                  </div>
                  <span className="font-mono text-[10px] text-muted-foreground">
                    {new Date(r.createdAt).toLocaleString()}
                  </span>
                </div>
                {r.scope && (
                  <p className="mt-2 flex flex-wrap items-center gap-1.5 font-mono text-[10px] text-muted-foreground">
                    <ShieldCheck className="size-3 text-violet-300" />
                    scope: {r.scope.authorizedPaths.join(", ")}
                    {r.scope.blockedPaths && r.scope.blockedPaths.length > 0 && (
                      <span className="flex items-center gap-1">
                        <ShieldOff className="size-3 text-rose-300" />
                        blocked: {r.scope.blockedPaths.join(", ")}
                      </span>
                    )}
                  </p>
                )}
                {r.findingsIngested !== undefined && (
                  <p className="mt-1 font-mono text-[10px] text-muted-foreground">
                    findings ingested: {r.findingsIngested}
                  </p>
                )}
                {r.note && (
                  <p className="mt-1 font-mono text-[10px] text-muted-foreground">{r.note}</p>
                )}
              </div>
            ))}
            {runs.length === 0 && !loading && (
              <div className="rounded-xl border border-dashed border-white/10 p-8 text-center text-sm text-muted-foreground">
                No runs recorded yet — Start Validation queues one the engine can pick up.
              </div>
            )}
          </TabsContent>
        </Tabs>
      </div>

      {/* Scope dialog — authorization artifacts for the queued run */}
      <Dialog open={scopeOpen} onOpenChange={setScopeOpen}>
        <DialogContent className="max-w-lg border-white/10 bg-[oklch(0.16_0.012_288)]">
          <DialogHeader>
            <DialogTitle>Scope this validation run</DialogTitle>
            <DialogDescription>
              The engine will only test what you authorize here. One path per
              line. Leave authorized empty for the whole project.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div>
              <label className="mb-1.5 block font-mono text-[10px] uppercase tracking-[0.14em] text-muted-foreground">
                Authorized paths (allow-list)
              </label>
              <Textarea
                value={scopeAuthorized}
                onChange={(e) => setScopeAuthorized(e.target.value)}
                placeholder={"/**\n/api/v2/**"}
                className="min-h-[80px] border-white/10 bg-black/30 font-mono text-xs"
              />
            </div>
            <div>
              <label className="mb-1.5 block font-mono text-[10px] uppercase tracking-[0.14em] text-muted-foreground">
                Blocked paths (never test)
              </label>
              <Textarea
                value={scopeBlocked}
                onChange={(e) => setScopeBlocked(e.target.value)}
                placeholder={"/admin/**\n/payment-internal/**"}
                className="min-h-[80px] border-white/10 bg-black/30 font-mono text-xs"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setScopeOpen(false)}>
              Cancel
            </Button>
            <Button
              disabled={startingRun}
              onClick={() => void handleStartValidation()}
              className="bg-violet-600 text-white hover:bg-violet-500"
            >
              <Play className="size-3.5" />
              {startingRun ? "Queueing…" : "Queue run"}
          </Button>
          </DialogFooter>
        </DialogContent>
        </Dialog>

      {/* Evidence dialog */}
      <Dialog
        open={evidencePath !== null}
        onOpenChange={(open) => !open && setEvidencePath(null)}
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
                  Recorded by the validator during the authorized run — nothing
                  simulated.
                </DialogDescription>
              </DialogHeader>
              <ScrollArea className="max-h-[55vh] pr-2">
                <div className="space-y-3">
                  {evidencePath.finding.evidence.map((ev) => (
                    <div
                      key={ev.id}
                      className="rounded-lg border border-white/[0.06] bg-black/30"
                    >
                      <div className="flex items-center justify-between border-b border-white/[0.06] px-3.5 py-2">
                        <span className="font-mono text-[11px] text-foreground/90">
                          {ev.label}
                        </span>
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
                  <p className="rounded-lg border border-violet-400/20 bg-violet-500/[0.06] p-3 text-xs leading-relaxed text-violet-100/85">
                    {evidencePath.finding.testerNote}
                  </p>
                </div>
              </ScrollArea>
              <DialogFooter className="gap-2">
                <Button
                  size="sm"
                  onClick={() => {
                    void handleSend(evidencePath);
                    setEvidencePath(null);
                  }}
                  className="bg-violet-600 text-white hover:bg-violet-500"
                >
                  <Send className="size-3.5" />
                  Send to Developer
                </Button>
                <Button variant="outline" onClick={() => setEvidencePath(null)}>
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

/* ------------------------------------------------------------------ */
/* Widgets                                                             */
/* ------------------------------------------------------------------ */

function StatTile({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4">
      <p className="text-[11px] font-medium uppercase tracking-[0.12em] text-muted-foreground">
        {label}
      </p>
      <p className="mt-1 font-mono text-xl font-semibold tracking-tight text-foreground">
        {value}
      </p>
    </div>
  );
}
