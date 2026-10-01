import {
  FileCode2,
  Search,
  Upload,
} from "lucide-react";
import { useMemo, useRef, useState } from "react";
import { Link, Navigate, useParams } from "react-router";
import { toast } from "sonner";
import { FindingWorkspace } from "@/components/developer/FindingWorkspace";
import { useFindings } from "@/hooks/useFindings";
import { useProjectSelection } from "@/hooks/useProjectSelection";
import { PanelShell } from "@/components/panels/PanelShell";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { cn } from "@/lib/utils";

const SEVERITY_DOT: Record<string, string> = {
  critical: "bg-rose-400",
  high: "bg-amber-400",
  medium: "bg-violet-400",
  low: "bg-white/40",
};

export default function DeveloperPanel() {
  const { findingId } = useParams();
  const { projectId } = useProjectSelection();
  const [query, setQuery] = useState("");
  const base = useFindings();
  const { findings, source, loading, finding: findFinding, importJson } = useMemo(() => {
    if (!projectId) return base;
    return {
      ...base,
      findings: base.findings.filter((f) => f.repo === projectId),
      finding: (id: string | undefined) =>
        id
          ? base.findings.find((f) => f.id === id && f.repo === projectId)
          : undefined,
    };
  }, [base, projectId]);
  const [importOpen, setImportOpen] = useState(false);
  const [importText, setImportText] = useState("");
  const [importing, setImporting] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return findings;
    return findings.filter(
      (f) =>
        f.title.toLowerCase().includes(q) ||
        f.id.toLowerCase().includes(q) ||
        f.repo.toLowerCase().includes(q) ||
        f.vulnerabilityType.toLowerCase().includes(q),
    );
  }, [findings, query]);

  const finding = findingId ? findFinding(findingId) : undefined;

  if (findingId && !finding) {
    return <Navigate to="/developer" replace />;
  }

  return (
    <PanelShell panel="developer" badge="Developer Workspace">
      {/* Body: sidebar + workspace */}
      <div className="mx-auto flex w-full max-w-[1500px] flex-1 gap-0">
        {/* Findings sidebar */}
        <aside className="hidden w-[320px] shrink-0 border-r border-white/[0.06] lg:block">
          <div className="sticky top-16 max-h-[calc(100vh-4rem)] overflow-hidden">
            <div className="p-4">
              <div className="relative">
                <Search className="pointer-events-none absolute left-3 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
                <Input
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Search findings…"
                  className="border-white/10 bg-white/[0.03] pl-9 text-sm"
                />
              </div>
              <p className="mt-2 font-mono text-[10px] text-muted-foreground">
                {loading
                  ? "loading findings…"
                  : source === "convex"
                    ? "source: orchestrator (Convex)"
                    : "source: seed — import JSON to replace"}
              </p>
            </div>
            <ScrollArea className="h-[calc(100vh-10rem)]">
              <ul className="space-y-1 px-3 pb-6">
                {filtered.map((f) => {
                  const isActive = f.id === findingId;
                  return (
                    <li key={f.id}>
                      <Link
                        to={`/developer/${f.id}`}
                        className={cn(
                          "block rounded-lg border px-3 py-3 transition-colors",
                          isActive
                            ? "border-violet-400/30 bg-violet-500/10"
                            : "border-transparent hover:border-white/[0.08] hover:bg-white/[0.03]",
                        )}
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-mono text-[10px] text-muted-foreground">
                            {f.id}
                          </span>
                          <span className="flex items-center gap-1.5">
                            <span className={cn("size-1.5 rounded-full", SEVERITY_DOT[f.severity])} />
                            <span className="font-mono text-[9px] uppercase tracking-wider text-muted-foreground">
                              {f.severity}
                            </span>
                          </span>
                        </div>
                        <p
                          className={cn(
                            "mt-1.5 truncate text-sm",
                            isActive ? "text-foreground" : "text-foreground/80",
                          )}
                        >
                          {f.title}
                        </p>
                        <p className="mt-1 truncate font-mono text-[10px] text-white/35">
                          {f.repo}/{f.file}
                        </p>
                      </Link>
                    </li>
                  );
                })}
                {findings.length === 0 && (
                  <li className="px-3 py-6 text-center text-sm text-muted-foreground">
                    No findings match “{query}”.
                  </li>
                )}
              </ul>
            </ScrollArea>
          </div>
        </aside>

        {/* Workspace */}
        <main className="min-w-0 flex-1 px-4 py-6 sm:px-6 lg:px-8">
          {finding ? (
            <FindingWorkspace finding={finding} engineBacked={source === "convex"} />
          ) : (            <div className="mx-auto max-w-2xl py-16 text-center">
              <span className="mx-auto flex size-14 items-center justify-center rounded-2xl border border-violet-400/25 bg-violet-500/10 text-violet-300 shadow-[0_0_40px_rgba(124,58,237,0.25)]">
                <FileCode2 className="size-6" />
              </span>
              <h1 className="mt-5 text-2xl font-semibold tracking-tight text-foreground">
                Developer Panel
              </h1>
              <p className="mx-auto mt-2 max-w-md text-sm leading-relaxed text-muted-foreground">
                Findings arrive here after authorized validation proves they are
                exploitable. Review the evidence, fix the code manually or with ECC,
                then re-run the attack to verify the fix.
              </p>
              <Separator className="my-8 opacity-40" />
              <p className="mb-4 text-left font-mono text-[10px] uppercase tracking-[0.18em] text-muted-foreground lg:hidden">
                Select a finding — open the panel on a larger screen to browse the list.
              </p>
              <div className="grid gap-3 text-left sm:grid-cols-3">
                {findings.map((f) => (
                  <Link
                    key={f.id}
                    to={`/developer/${f.id}`}
                    className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4 transition-colors hover:border-violet-400/25 hover:bg-white/[0.04]"
                  >
                    <span className="font-mono text-[10px] text-muted-foreground">{f.id}</span>
                    <p className="mt-1.5 line-clamp-2 text-sm text-foreground/90">{f.title}</p>
                    <span className={cn("mt-2 inline-block size-1.5 rounded-full", SEVERITY_DOT[f.severity])} />
                  </Link>
                ))}
              </div>
            </div>
          )}
        </main>
      </div>

      {/* Orchestrator JSON import */}
      <Dialog open={importOpen} onOpenChange={setImportOpen}>
        <DialogContent className="max-w-2xl border-white/10 bg-[oklch(0.16_0.012_288)]">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-base">
              <Upload className="size-4 text-violet-300" />
              Import orchestrator JSON
            </DialogTitle>
            <DialogDescription>
              Paste the JSON written by orchestrator.py (or upload a file). The
              re-test verdicts are taken from the imported attack steps —
              nothing is simulated.
            </DialogDescription>
          </DialogHeader>

          <input
            ref={fileInputRef}
            type="file"
            accept="application/json,.json"
            className="hidden"
            onChange={async (e) => {
              const file = e.target.files?.[0];
              if (!file) return;
              const text = await file.text();
              setImportText(text);
              e.target.value = "";
            }}
          />

          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => fileInputRef.current?.click()}
              >
                <Upload className="size-3.5" />
                Upload .json file
              </Button>
              {importText && (
                <span className="font-mono text-[10px] text-muted-foreground">
                  {importText.length.toLocaleString()} chars loaded
                </span>
              )}
            </div>
            <textarea
              value={importText}
              onChange={(e) => setImportText(e.target.value)}
              placeholder='{ "findings": [ ... ] } — purpleguard.findings/v1'
              className="h-56 w-full resize-none rounded-lg border border-white/10 bg-black/30 p-3 font-mono text-[11px] text-foreground/90 outline-none placeholder:text-white/25"
            />
          </div>

          <DialogFooter className="gap-2">
            <Button variant="outline" onClick={() => setImportOpen(false)}>
              Cancel
            </Button>
            <Button
              disabled={importing || importText.trim().length === 0}
              onClick={async () => {
                setImporting(true);
                try {
                  const outcome = await importJson(importText);
                  if (outcome.ok) {
                    toast.success(
                      `Imported ${outcome.count} finding${outcome.count === 1 ? "" : "s"}`,
                      { description: "Verdicts now come from the imported engine run." },
                    );
                    setImportOpen(false);
                    setImportText("");
                  } else {
                    toast.error("Import failed", {
                      description: outcome.errors.join(" "),
                    });
                  }
                } finally {
                  setImporting(false);
                }
              }}
              className="bg-violet-600 text-white hover:bg-violet-500"
            >
              Import findings
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </PanelShell>
  );
}
