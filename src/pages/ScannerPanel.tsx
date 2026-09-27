import { Play, ScanLine } from "lucide-react";
import { useState } from "react";
import { useMutation } from "convex/react";
import { toast } from "sonner";
import { api } from "@/convex/_generated/api";
import type { EngineFinding } from "@/components/developer/ingest";
import { PanelShell } from "@/components/panels/PanelShell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/ui/tabs";
import { usePurpleGuardData } from "@/hooks/usePurpleGuardData";
import { useProjectSelection } from "@/hooks/useProjectSelection";
import { cn } from "@/lib/utils";

const SEVERITY_STYLES: Record<string, string> = {
  critical: "border-rose-400/30 bg-rose-400/10 text-rose-300",
  high: "border-amber-400/30 bg-amber-400/10 text-amber-300",
  medium: "border-violet-400/30 bg-violet-400/10 text-violet-300",
  low: "border-white/15 bg-white/[0.05] text-muted-foreground",
};

/** Static-analysis panel (ported from the legacy "Scanner" tab).
 *  Queues a real workflowRun of kind "scan"; the engine's engine side runs
 *  SecurityScanner only — no live target, no adversarial claims. */
export default function ScannerPanel() {
  const { projectId } = useProjectSelection();
  const { loading, findings, runs } = usePurpleGuardData(projectId ?? undefined);
  const startRun = useMutation(api.workflow.startRun);
  const [starting, setStarting] = useState(false);
  const [scopeAuthorized, setScopeAuthorized] = useState("/**");
  const [openId, setOpenId] = useState<string | null>(null);

  const scanRuns = runs.filter((r) => r.kind === "scan");

  const handleScan = async () => {
    const target = projectId ?? findings[0]?.repo ?? "";
    if (!target) {
      toast.error("No project selected", {
        description: "Connect or select a project in the Console first.",
      });
      return;
    }
    setStarting(true);
    try {
      const authorizedPaths = scopeAuthorized
        .split("\n")
        .map((s) => s.trim())
        .filter(Boolean);
      await startRun({
        projectId: target,
        kind: "scan",
        note: "Static scan requested from the Scanner panel",
        scope: { authorizedPaths: authorizedPaths.length > 0 ? authorizedPaths : ["/**"] },
      });
      toast.success("Static scan queued", {
        description:
          "The engine will run the static scanner only. Findings appear here when ingested.",
      });
    } catch (e) {
      toast.error("Could not queue scan", {
        description: e instanceof Error ? e.message : "Unknown error",
      });
    } finally {
      setStarting(false);
    }
  };

  return (
    <PanelShell panel="scanner" badge="Static Analysis">
      <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
          <div>
            <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted-foreground">
              static scanner
            </p>
            <h1 className="mt-1 text-2xl font-semibold tracking-tight text-foreground sm:text-3xl">
              Run the PurpleGuard static analysis engine.
            </h1>
            <p className="mt-2 max-w-2xl text-sm text-muted-foreground">
              Rule-based scan (PG rules) of the authorized scope. Static
              findings are candidates — adversarial validation happens in the
              Hacker panel, and is labeled as such everywhere.
            </p>
          </div>
          <Button
            size="sm"
            disabled={starting || loading || (projectId === null && findings.length === 0)}
            className="bg-violet-600 text-white shadow-[0_0_24px_rgba(124,58,237,0.4)] hover:bg-violet-500"
            onClick={() => void handleScan()}
          >
            <Play className="size-3.5" />
            {starting ? "Queueing…" : "Run static scan"}
          </Button>
        </div>

        <div className="mt-6 rounded-xl border border-white/[0.06] bg-white/[0.02] p-4">
          <label className="mb-1.5 block font-mono text-[10px] uppercase tracking-[0.14em] text-muted-foreground">
            Authorized paths (one per line — the engine scans nothing outside this)
          </label>
          <Textarea
            value={scopeAuthorized}
            onChange={(e) => setScopeAuthorized(e.target.value)}
            placeholder={"/**\nsrc/**"}
            className="min-h-[64px] border-white/10 bg-black/30 font-mono text-xs"
          />
        </div>

        <Tabs defaultValue="findings" className="mt-8 space-y-4">
          <TabsList className="bg-white/[0.03]">
            <TabsTrigger value="findings" className="gap-1.5">
              <ScanLine className="size-3.5" />
              Findings ({findings.length})
            </TabsTrigger>
            <TabsTrigger value="runs" className="gap-1.5">
              Scan runs ({scanRuns.length})
            </TabsTrigger>
          </TabsList>

          <TabsContent value="findings" className="mt-0 space-y-3">
            {findings.map((f: EngineFinding) => {
              const isStatic = f.runId === undefined || f.runId === null;
              const open = openId === f.id;
              return (
                <div
                  key={f.id}
                  className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4"
                >
                  <button
                    type="button"
                    className="flex w-full flex-wrap items-center justify-between gap-2 text-left"
                    onClick={() => setOpenId(open ? null : f.id)}
                  >
                    <div className="flex min-w-0 flex-wrap items-center gap-2">
                      <Badge
                        variant="outline"
                        className={cn(
                          "font-mono text-[10px] uppercase tracking-wider",
                          SEVERITY_STYLES[f.severity] ?? "",
                        )}
                      >
                        {f.severity}
                      </Badge>
                      <Badge
                        variant="outline"
                        className="border-white/15 bg-white/[0.05] font-mono text-[10px] text-muted-foreground"
                      >
                        static · candidate
                      </Badge>
                      <span className="truncate text-sm font-semibold text-foreground">
                        {f.title}
                      </span>
                    </div>
                    <span className="shrink-0 font-mono text-[10px] text-muted-foreground">
                      {f.file} · {f.location}
                    </span>
                  </button>
                  {open && (
                    <div className="mt-3 space-y-3 border-t border-white/[0.06] pt-3">
                      <p className="text-sm text-muted-foreground">{f.explanation}</p>
                      {f.vulnerableCode && (
                        <pre className="max-h-48 overflow-auto rounded-lg border border-white/10 bg-black/40 p-3 font-mono text-[11px] text-violet-200">
                          {f.vulnerableCode}
                        </pre>
                      )}
                      <ol className="space-y-1 border-l border-white/[0.08] pl-4 font-mono text-[11px] text-muted-foreground">
                        {(f.attackPath ?? []).map((step, i) => (
                          <li key={i}>{step}</li>
                        ))}
                      </ol>
                      <p className="font-mono text-[10px] text-muted-foreground">
                        {f.remediation}
                      </p>
                    </div>
                  )}
                </div>
              );
            })}
            {findings.length === 0 && !loading && (
              <p className="rounded-xl border border-dashed border-white/10 p-8 text-center text-sm text-muted-foreground">
                No findings ingested yet — queue a static scan, then the engine
                picks it up and pushes real results here.
              </p>
            )}
          </TabsContent>

          <TabsContent value="runs" className="mt-0 space-y-3">
            {scanRuns.map((r) => (
              <div key={r._id} className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-mono text-[11px] text-foreground/90">
                    scan · {r.projectId}
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
                {r.note && <p className="mt-1 font-mono text-[10px] text-muted-foreground">{r.note}</p>}
                {r.findingsIngested !== undefined && (
                  <p className="mt-1 font-mono text-[10px] text-muted-foreground">
                    findings ingested: {r.findingsIngested}
                  </p>
                )}
              </div>
            ))}
            {scanRuns.length === 0 && (
              <div className="rounded-xl border border-dashed border-white/10 p-8 text-center text-sm text-muted-foreground">
                No scan runs yet.
              </div>
            )}
          </TabsContent>
        </Tabs>
      </div>
    </PanelShell>
  );
}
