import { Bot, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { useMutation, useQuery } from "convex/react";
import { toast } from "sonner";
import { api } from "@/convex/_generated/api";
import type { EngineFinding } from "@/components/developer/ingest";
import { PanelShell } from "@/components/panels/PanelShell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { usePurpleGuardData } from "@/hooks/usePurpleGuardData";
import { useProjectSelection } from "@/hooks/useProjectSelection";
import { cn } from "@/lib/utils";

export default function EngineerPanel() {
  const { projectId } = useProjectSelection();
  const { loading, findings, runs } = usePurpleGuardData(projectId ?? undefined);
  const pendingApprovals = useQuery(api.approvals.pending);
  const requestApproval = useMutation(api.approvals.requestApproval);
  const startRun = useMutation(api.workflow.startRun);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [sending, setSending] = useState(false);
  const [queueing, setQueueing] = useState(false);

  const selected =
    findings.find((f: EngineFinding) => f.id === selectedId) ?? null;
  const remediationRuns = runs.filter((r) => r.kind === "remediation");
  const proposed = selected?.proposedPatch ?? selected?.fixedCode ?? null;
  const pendingForSelected = (pendingApprovals ?? []).filter(
    (d) => d.findingId === selectedId,
  );

  const handleApprove = async () => {
    if (!selected || !proposed) return;
    setSending(true);
    try {
      await requestApproval({
        findingId: selected.id,
        source: "ai",
        buffer: proposed,
      });
      toast.success("Fix sent to the engine (approval gate)", {
        description:
          "The engine applies the approved buffer to its local clone, re-attacks, and posts the real verdict.",
      });
    } catch (e) {
      toast.error("Could not queue approval", {
        description: e instanceof Error ? e.message : "Unknown error",
      });
    } finally {
      setSending(false);
    }
  };

  const handleFullLoop = async () => {
    const target = projectId ?? findings[0]?.repo ?? "";
    if (!target) return;
    setQueueing(true);
    try {
      await startRun({
        projectId: target,
        kind: "remediation",
        note: "Approve & apply requested from the AI Engineer panel — the engine runs its own approval gate before touching code",
      });
      toast.success("Full secure loop queued", {
        description:
          "The engine discovers → validates → proposes → applies (after its own gate) → re-attacks → verifies.",
      });
    } catch (e) {
      toast.error("Could not queue the loop", {
        description: e instanceof Error ? e.message : "Unknown error",
      });
    } finally {
      setQueueing(false);
    }
  };

  return (
    <PanelShell panel="engineer" badge="AI Engineer">
      <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
          <div>
            <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted-foreground">
              proposed fixes · approval gated
            </p>
            <h1 className="mt-1 text-2xl font-semibold tracking-tight text-foreground sm:text-3xl">
              Review the fix. Approve it. The engine proves it.
            </h1>
            <p className="mt-2 max-w-2xl text-sm text-muted-foreground">
              Patches proposed by the engine's remediation adapter. The UI
              never modifies code: approvals are applied by the engine against
              its local clone and verified by a real re-attack.
            </p>
          </div>
          <Button
            size="sm"
            variant="outline"
            disabled={queueing || loading || (projectId === null && findings.length === 0)}
            onClick={() => void handleFullLoop()}
          >
            <Bot className={cn("size-3.5", queueing && "animate-pulse")} />
            {queueing ? "Queueing…" : "Run full secure loop"}
          </Button>
        </div>

        <div className="mt-8 grid gap-6 lg:grid-cols-[380px_1fr]">
          <div className="space-y-2">
            {findings.map((f: EngineFinding) => (
              <button
                key={f.id}
                type="button"
                onClick={() => setSelectedId(f.id)}
                className={cn(
                  "w-full rounded-xl border p-3.5 text-left transition",
                  f.id === selectedId
                    ? "border-violet-400/40 bg-violet-500/[0.08]"
                    : "border-white/[0.06] bg-white/[0.02] hover:border-violet-400/20",
                )}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="truncate text-sm font-medium text-foreground">
                    {f.title}
                  </span>
                  <Badge
                    variant="outline"
                    className="shrink-0 font-mono text-[10px] uppercase"
                  >
                    {f.severity}
                  </Badge>
                </div>
                <p className="mt-1 font-mono text-[10px] text-muted-foreground">
                  {f.file} · {f.location}
                </p>
              </button>
            ))}
            {findings.length === 0 && !loading && (
              <p className="rounded-xl border border-dashed border-white/10 p-6 text-center text-sm text-muted-foreground">
                No findings yet.
              </p>
            )}
          </div>

          <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-5">
            {!selected ? (
              <p className="p-6 text-center text-sm text-muted-foreground">
                Select a finding to review its proposed fix.
              </p>
            ) : (
              <div className="space-y-4">
                <div>
                  <h2 className="text-lg font-semibold text-foreground">
                    {selected.title}
                  </h2>
                  <p className="mt-1 text-sm text-muted-foreground">
                    {selected.explanation}
                  </p>
                </div>

                {selected.vulnerableCode && (
                  <div>
                    <p className="mb-1.5 font-mono text-[10px] uppercase tracking-[0.14em] text-muted-foreground">
                      Vulnerable code
                    </p>
                    <pre className="max-h-56 overflow-auto rounded-lg border border-rose-400/15 bg-rose-400/[0.03] p-3 font-mono text-[11px] text-rose-100/80">
                      {selected.vulnerableCode}
                    </pre>
                  </div>
                )}

                {proposed ? (
                  <div>
                    <p className="mb-1.5 font-mono text-[10px] uppercase tracking-[0.14em] text-violet-300">
                      Proposed secure code
                    </p>
                    <pre className="max-h-56 overflow-auto rounded-lg border border-emerald-400/15 bg-emerald-400/[0.03] p-3 font-mono text-[11px] text-emerald-100/80">
                      {proposed}
                    </pre>
                  </div>
                ) : (
                  <p className="rounded-lg border border-amber-400/20 bg-amber-400/[0.04] p-3 text-xs text-amber-200/80">
                    No proposed fix exists yet for this finding. Run the full
                    secure loop so the engine's remediation adapter can
                    generate one — no fix is invented here.
                  </p>
                )}

                <div className="rounded-lg border border-amber-400/15 bg-amber-400/[0.03] p-3">
                  <p className="text-xs font-medium text-amber-200/90">
                    Approval required
                  </p>
                  <p className="mt-1 text-[11px] leading-5 text-muted-foreground">
                    The engine will not modify the project until a developer
                    explicitly approves. Verdicts come only from the engine's
                    re-attack.
                  </p>
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  <Button
                    size="sm"
                    disabled={!proposed || sending}
                    className="bg-violet-600 text-white hover:bg-violet-500"
                    onClick={() => void handleApprove()}
                  >
                    <ShieldCheck className="size-3.5" />
                    {sending ? "Sending…" : "Approve & apply fix"}
                  </Button>
                  {pendingForSelected.length > 0 && (
                    <Badge
                      variant="outline"
                      className="border-cyan-400/25 bg-cyan-400/10 font-mono text-[10px] text-cyan-300"
                    >
                      {pendingForSelected.length} approval
                      {pendingForSelected.length === 1 ? "" : "s"} pending with
                      engine
                    </Badge>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>

        <div className="mt-8">
          <h2 className="font-mono text-[11px] uppercase tracking-[0.14em] text-muted-foreground">
            Full-loop runs
          </h2>
          <div className="mt-3 space-y-2">
            {remediationRuns.map((r) => (
              <div
                key={r._id}
                className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-3.5"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-mono text-[11px] text-foreground/90">
                    remediation · {r.projectId}
                  </span>
                  <Badge
                    variant="outline"
                    className={cn(
                      "font-mono text-[10px]",
                      r.status === "completed"
                        ? "border-emerald-400/25 bg-emerald-400/10 text-emerald-300"
                        : r.status === "failed"
                          ? "border-rose-400/30 bg-rose-400/10 text-rose-300"
                          : "border-cyan-400/25 bg-cyan-400/10 text-cyan-300",
                    )}
                  >
                    {r.status}
                  </Badge>
                </div>
                {r.note && (
                  <p className="mt-1 font-mono text-[10px] text-muted-foreground">
                    {r.note}
                  </p>
                )}
              </div>
            ))}
            {remediationRuns.length === 0 && (
              <p className="font-mono text-[10px] text-muted-foreground">
                No full-loop runs yet.
              </p>
            )}
          </div>
        </div>
      </div>
    </PanelShell>
  );
}
