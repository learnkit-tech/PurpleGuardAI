import { AnimatePresence, motion } from "framer-motion";
import {
  Ban,
  Check,
  Clock,
  Code2,
  Eye,
  FileCode2,
  FlaskConical,
  GitCompare,
  Lock,
  Pencil,
  Play,
  Save,
  ShieldCheck,
  ShieldX,
  Sparkles,
  Target,
  Terminal,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import {
  initialState,
  type FindingDetailData,
  type FindingState,
  type FixSource,
} from "@/components/developer/data";
import { runReTest } from "@/components/developer/engineFindings";
import { useApprovals } from "@/hooks/useApprovals";
import { useRevalidation } from "@/hooks/useRevalidation";
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
import { Separator } from "@/components/ui/separator";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  diffLines,
  type DiffLine,
  type DiffLineType,
} from "@/lib/diff";
import { cn } from "@/lib/utils";
import { toast } from "sonner";

/* ------------------------------------------------------------------ */
/* Severity + verification styling                                     */
/* ------------------------------------------------------------------ */

const SEVERITY_STYLES: Record<FindingDetailData["severity"], string> = {
  critical: "border-rose-400/30 bg-rose-400/10 text-rose-300",
  high: "border-amber-400/30 bg-amber-400/10 text-amber-300",
  medium: "border-violet-400/30 bg-violet-400/10 text-violet-300",
  low: "border-white/15 bg-white/[0.05] text-muted-foreground",
};

const VERIFICATION_META: Record<
  FindingState["verification"],
  { label: string; styles: string; icon: typeof ShieldCheck }
> = {
  unverified: {
    label: "Unverified",
    styles: "border-white/15 bg-white/[0.05] text-muted-foreground",
    icon: Eye,
  },
  vulnerable: {
    label: "Still vulnerable",
    styles: "border-rose-400/30 bg-rose-400/10 text-rose-300",
    icon: ShieldX,
  },
  verified: {
    label: "Verified fixed",
    styles: "border-emerald-400/25 bg-emerald-400/10 text-emerald-300",
    icon: ShieldCheck,
  },
};

const DIFF_LINE_STYLES: Record<DiffLineType, string> = {
  context: "text-muted-foreground",
  added: "bg-emerald-400/[0.07] text-emerald-200",
  removed: "bg-rose-400/[0.07] text-rose-200",
};

/* ------------------------------------------------------------------ */
/* Small building blocks                                               */
/* ------------------------------------------------------------------ */

function MetaRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-baseline justify-between gap-4 py-1.5">
      <span className="shrink-0 font-mono text-[10px] uppercase tracking-[0.14em] text-muted-foreground">
        {label}
      </span>
      <span className="truncate text-right font-mono text-[11px] text-foreground/90">
        {value}
      </span>
    </div>
  );
}

function EvidenceViewer({ finding }: { finding: FindingDetailData }) {
  const [active, setActive] = useState(finding.evidence[0]?.id ?? "");
  const evidence =
    finding.evidence.find((e) => e.id === active) ?? finding.evidence[0];

  return (
    <div className="rounded-xl border border-white/[0.06] bg-white/[0.02]">
      <div className="flex flex-wrap gap-1 border-b border-white/[0.06] p-2">
        {finding.evidence.map((item) => (
          <button
            key={item.id}
            type="button"
            onClick={() => setActive(item.id)}
            className={cn(
              "rounded-md px-2.5 py-1.5 font-mono text-[11px] transition-colors",
              evidence?.id === item.id
                ? "bg-violet-500/15 text-violet-200"
                : "text-muted-foreground hover:bg-white/[0.04] hover:text-foreground",
            )}
          >
            {item.label}
          </button>
        ))}
      </div>
      {evidence && (
        <pre className="max-h-56 overflow-auto p-4 font-mono text-[11px] leading-relaxed text-foreground/85">
          {evidence.content}
        </pre>
      )}
      <div className="flex items-center gap-2 border-t border-white/[0.06] px-4 py-2.5 text-[11px] text-muted-foreground">
        <Lock className="size-3 shrink-0 text-emerald-400" />
        {finding.testerNote}
      </div>
    </div>
  );
}

function DiffView({ oldCode, newCode }: { oldCode: string; newCode: string }) {
  const hunks = useMemo(() => diffLines(oldCode, newCode), [oldCode, newCode]);

  if (hunks.length === 0) {
    return (
      <div className="flex h-32 items-center justify-center rounded-xl border border-dashed border-white/10 text-sm text-muted-foreground">
        No changes between the two versions.
      </div>
    );
  }

  return (
    <div className="overflow-hidden rounded-xl border border-white/[0.06] bg-white/[0.02]">
      {hunks.map((hunk, hi) => (
        <div key={hi} className={cn(hi > 0 && "border-t border-white/[0.06]")}>
          <div className="bg-white/[0.03] px-4 py-1.5 font-mono text-[10px] text-muted-foreground">
            {hunk.header}
          </div>
          {hunk.lines.map((line: DiffLine, li: number) => (
            <div
              key={li}
              className={cn(
                "flex items-start gap-3 px-4 py-0.5 font-mono text-[11.5px] leading-relaxed",
                DIFF_LINE_STYLES[line.type],
              )}
            >
              <span className="w-8 shrink-0 select-none text-right text-white/25">
                {line.oldNumber ?? ""}
              </span>
              <span className="w-8 shrink-0 select-none text-right text-white/25">
                {line.newNumber ?? ""}
              </span>
              <span className="w-3 shrink-0 select-none">
                {line.type === "added" ? "+" : line.type === "removed" ? "−" : " "}
              </span>
              <pre className="min-w-0 flex-1 whitespace-pre-wrap break-words">
                {line.text || " "}
              </pre>
            </div>
          ))}
        </div>
      ))}
    </div>
  );
}

function CodeEditor({
  code,
  onChange,
  disabled,
}: {
  code: string;
  onChange: (next: string) => void;
  disabled?: boolean;
}) {
  const lineCount = useMemo(() => code.split("\n").length, [code]);

  return (
    <div className="overflow-hidden rounded-xl border border-white/[0.06] bg-white/[0.02]">
      <div className="flex items-center justify-between border-b border-white/[0.06] bg-white/[0.03] px-4 py-2">
        <span className="flex items-center gap-2 font-mono text-[11px] text-muted-foreground">
          <FileCode2 className="size-3.5" />
          workspace buffer
        </span>
        <span className="font-mono text-[10px] text-white/30">
          {lineCount} lines
        </span>
      </div>
      <div className="relative">
        <textarea
          spellCheck={false}
          disabled={disabled}
          value={code}
          onChange={(e) => onChange(e.target.value)}
          onKeyDown={(e) => {
            // Tab inserts two spaces instead of leaving the editor.
            if (e.key === "Tab") {
              e.preventDefault();
              const el = e.currentTarget;
              const start = el.selectionStart;
              const end = el.selectionEnd;
              const next = code.slice(0, start) + "  " + code.slice(end);
              onChange(next);
              requestAnimationFrame(() => {
                el.selectionStart = el.selectionEnd = start + 2;
              });
            }
          }}
          className="h-[380px] w-full resize-none bg-transparent p-4 font-mono text-[12px] leading-relaxed text-foreground/90 outline-none placeholder:text-muted-foreground disabled:opacity-60"
        />
      </div>
    </div>
  );
}

function ReTestPanel({
  state,
  finding,
  log,
  onRun,
  running,
  waiting,
  engineBacked,
}: {
  state: FindingState;
  finding: FindingDetailData;
  log: string[];
  onRun: () => void;
  running: boolean;
  waiting: boolean;
  engineBacked: boolean;
}) {
  const verdict = state.verification;

  return (
    <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <span className="flex size-9 items-center justify-center rounded-lg border border-white/10 bg-white/[0.03] text-violet-300">
            <FlaskConical className="size-4" />
          </span>
          <div>
            <h3 className="text-sm font-semibold tracking-tight text-foreground">
              Authorized re-test
            </h3>
            <p className="text-xs text-muted-foreground">
              {engineBacked
                ? "Queues a fresh authorized re-attack — the verdict comes from the engine."
                : "Replays the verdict recorded by the orchestrator run for this finding."}
            </p>
          </div>
        </div>
        <Button
          size="sm"
          onClick={onRun}
          disabled={running || waiting}
          className="bg-violet-600 text-white shadow-[0_0_20px_rgba(124,58,237,0.35)] hover:bg-violet-500"
        >
          <Play className="size-3.5" />
          {waiting
            ? "Waiting for engine…"
            : running
              ? "Re-testing…"
              : engineBacked
                ? "Re-run validation"
                : "Replay recorded verdict"}
        </Button>
      </div>

      <AnimatePresence>
        {running && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="mt-3 h-0.5 overflow-hidden rounded-full bg-white/[0.06]"
          >
            <motion.div
              className="h-full w-1/3 rounded-full bg-gradient-to-r from-violet-500 to-cyan-300"
              animate={{ x: ["-100%", "300%"] }}
              transition={{ duration: 1.1, repeat: Infinity, ease: "linear" }}
            />
          </motion.div>
        )}
      </AnimatePresence>

      {waiting && (
        <motion.div
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          className="mt-3 flex items-center gap-3 rounded-lg border border-cyan-400/25 bg-cyan-400/[0.06] px-4 py-3"
        >
          <Clock className="size-5 shrink-0 animate-pulse text-cyan-300" />
          <div>
            <p className="font-mono text-sm font-semibold tracking-wide text-cyan-200">
              WAITING FOR ENGINE
            </p>
            <p className="text-xs text-cyan-200/70">
              Re-attack queued — the engine will re-run the authorized attack
              path and post the real verdict back. Nothing is simulated here.
            </p>
          </div>
        </motion.div>
      )}

      {log.length > 0 && (
        <pre className="mt-3 max-h-44 overflow-auto rounded-lg border border-white/[0.06] bg-black/40 p-3 font-mono text-[10.5px] leading-relaxed text-emerald-200/90">
          {log.join("\n")}
        </pre>
      )}

      {finding.attackSteps && finding.attackSteps.length > 0 && (
        <div className="mt-3 space-y-1.5">
          <p className="font-mono text-[10px] uppercase tracking-[0.14em] text-muted-foreground">
            Recorded attack steps · verdicts from the orchestrator run
          </p>
          {finding.attackSteps.map((step) => (
            <div
              key={step.name}
              className="flex items-start gap-2.5 rounded-lg border border-white/[0.05] bg-white/[0.02] px-3 py-2"
            >
              <span
                className={cn(
                  "mt-0.5 size-1.5 shrink-0 rounded-full",
                  step.verdict === "blocked" ? "bg-emerald-400" : "bg-rose-400",
                )}
              />
              <div className="min-w-0">
                <p className="text-xs text-foreground/90">{step.name}</p>
                <p className="font-mono text-[10px] text-muted-foreground">
                  {step.verdict === "blocked" ? "BLOCKED" : "EXPLOITED"} · {step.criteria}
                </p>
              </div>
            </div>
          ))}
        </div>
      )}

      {verdict === "verified" && (
        <motion.div
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          className="mt-3 flex items-center gap-3 rounded-lg border border-emerald-400/25 bg-emerald-400/[0.07] px-4 py-3"
        >
          <ShieldCheck className="size-5 shrink-0 text-emerald-400" />
          <div>
            <p className="font-mono text-sm font-semibold tracking-wide text-emerald-300">
              VERIFIED FIXED
            </p>
            <p className="text-xs text-emerald-200/70">
              The authorized attack no longer succeeds against this code.
            </p>
          </div>
        </motion.div>
      )}
      {verdict === "vulnerable" && (
        <motion.div
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          className="mt-3 flex items-center gap-3 rounded-lg border border-rose-400/25 bg-rose-400/[0.07] px-4 py-3"
        >
          <ShieldX className="size-5 shrink-0 text-rose-400" />
          <div>
            <p className="font-mono text-sm font-semibold tracking-wide text-rose-300">
              STILL VULNERABLE
            </p>
            <p className="text-xs text-rose-200/70">
              The validator reproduced the attack on the current code.
              {finding.vulnerableMarker && (
                <>
                  {" "}Marker:{" "}
                  <code className="rounded bg-black/40 px-1 font-mono text-[10px]">
                    {finding.vulnerableMarker}
                  </code>
                </>
              )}
            </p>
          </div>
        </motion.div>
      )}
      {verdict === "unverified" && (
        <p className="mt-3 flex items-center gap-2 text-xs text-muted-foreground">
          <Eye className="size-3.5" />
          Not re-tested yet — applying a patch or saving manual edits queues a re-test.
        </p>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Main finding workspace                                              */
/* ------------------------------------------------------------------ */

const STEP_LABELS = ["Finding", "Evidence", "Code", "Fix", "Verify"] as const;

export function FindingWorkspace({
  finding,
  engineBacked,
}: {
  finding: FindingDetailData;
  /** True when the finding came from the orchestrator (Convex); re-attacks then run in the engine, not the browser. */
  engineBacked: boolean;
}) {
  const [state, setState] = useState<FindingState>(() => initialState(finding));
  const [savedCode, setSavedCode] = useState(finding.vulnerableCode);
  const [fixProposal, setFixProposal] = useState(false);
  const [applyConfirm, setApplyConfirm] = useState(false);
  const [running, setRunning] = useState(false);
  const [retestLog, setRetestLog] = useState<string[]>([]);
  const [historyOpen, setHistoryOpen] = useState(false);
  const timerRef = useRef<number | null>(null);
  const [waitingEngine, setWaitingEngine] = useState(false);
  const {
    submit: submitApproval,
    pendingForFinding: approvalPending,
    latest: latestApproval,
  } = useApprovals(finding.id);
  const { queue: queueRevalidation, latest: latestRevalidation } =
    useRevalidation(finding.id);
  const initializedFromApproval = useRef(false);
  // Approval/revalidation records processed for verdicts, so a Convex
  // re-emit of the same record doesn't duplicate history entries or toasts.
  const seenApprovalId = useRef<string | null>(null);
  const seenRevalidationId = useRef<string | null>(null);

  const hasEdits = state.code !== savedCode;
  const diffForReview = useMemo(
    () => diffLines(state.code, finding.proposedPatch),
    [state.code, finding.proposedPatch],
  );
  const proposalMatchesWorkspace = diffForReview.length === 0;

  const currentStep = useMemo(() => {
    if (state.verification !== "unverified") return 5;
    if (savedCode !== finding.vulnerableCode) return 4;
    if (hasEdits) return 3;
    return 2;
  }, [state.verification, savedCode, hasEdits, finding.vulnerableCode]);

  // Engine-resolved approvals flow the real re-attack verdict back in.
  useEffect(() => {
    if (
      !latestApproval ||
      latestApproval.status !== "applied" ||
      !latestApproval.verdict ||
      seenApprovalId.current === latestApproval._id
    )
      return;
    seenApprovalId.current = latestApproval._id;
    const fixed = latestApproval.verdict === "VERIFIED_FIXED";
    setRetestLog([
      ...(latestApproval.log ?? []),
      `[verdict] ${fixed ? "VERIFIED FIXED" : "STILL VULNERABLE"} — recorded by the engine re-attack`,
    ]);
    setState((prev) => ({
      ...prev,
      verification: fixed ? "verified" : "vulnerable",
      history: [
        ...prev.history,
        {
          at: Date.now(),
          source: latestApproval.source === "ai" ? "ai" : "manual",
          summary: fixed
            ? "Engine re-attack blocked — verdict recorded"
            : "Engine re-attack still exploitable — verdict recorded",
          fixed,
        },
      ],
    }));
  }, [latestApproval]);

  // Engine-resolved revalidations do the same for queued re-tests.
  useEffect(() => {
    if (
      !latestRevalidation ||
      latestRevalidation.status !== "resolved" ||
      !latestRevalidation.verdict ||
      seenRevalidationId.current === latestRevalidation._id
    )
      return;
    seenRevalidationId.current = latestRevalidation._id;
    const fixed = latestRevalidation.verdict === "VERIFIED_FIXED";
    setWaitingEngine(false);
    setRunning(false);
    setRetestLog([
      ...(latestRevalidation.log ?? []),
      `[verdict] ${fixed ? "VERIFIED FIXED" : "STILL VULNERABLE"} — recorded by the engine re-attack`,
    ]);
    setState((prev) => ({
      ...prev,
      verification: fixed ? "verified" : "vulnerable",
      history: [
        ...prev.history,
        {
          at: Date.now(),
          source: prev.fixSource ?? "manual",
          summary: fixed
            ? "Engine re-attack blocked — queued validation verified the fix"
            : "Engine re-attack still exploitable — queued validation failed",
          fixed,
        },
      ],
    }));
    if (fixed) {
      toast.success("VERIFIED FIXED", {
        description: "Verdict recorded by the engine re-attack.",
      });
    } else {
      toast.error("STILL VULNERABLE", {
        description: "Verdict recorded by the engine re-attack.",
      });
    }
  }, [latestRevalidation]);

  // Restore the workspace buffer the engine last applied, if any.
  // Runs in a task (not synchronously in the effect body) to avoid cascading
  // renders; the once-guard keeps it a one-shot restore per finding.
  useEffect(() => {
    if (initializedFromApproval.current || !latestApproval) return;
    initializedFromApproval.current = true;
    if (latestApproval.status === "applied" && latestApproval.code) {
      const applied = latestApproval;
      const task = setTimeout(() => {
        setSavedCode(applied.code);
        setState((prev) => ({
          ...prev,
          code: applied.code,
          fixSource: applied.source === "ai" ? "ai" : "manual",
        }));
      }, 0);
      return () => clearTimeout(task);
    }
  }, [latestApproval]);

  const applyFix = (source: Exclude<FixSource, null>) => {
    const nextCode = source === "ai" ? finding.fixedCode : state.code;
    setState((prev) => ({
      ...prev,
      code: nextCode,
      verification: "unverified",
      fixSource: source,
      attempts: prev.attempts + 1,
      history: [
        ...prev.history,
        {
          at: Date.now(),
          source,
          summary:
            source === "ai"
              ? `Applied ECC-proposed patch for ${finding.vulnerabilityType}`
              : "Applied manual edits from workspace buffer",
          fixed: false,
        },
      ],
    }));
    setSavedCode(nextCode);
    setApplyConfirm(false);
    setFixProposal(false);
    // Close the loop: the engine polls this approval, applies the patch,
    // re-attacks, and records the real verdict back into the finding.
    if (engineBacked) {
      void submitApproval(source, nextCode);
      toast.success("Approval queued for the engine", {
        description:
          "The engine will apply this code, re-attack, and write the verdict back.",
      });
    } else {
      toast.success("Patch applied to workspace", {
        description: "Run the re-test to verify the fix.",
      });
    }
  };

  const handleReTest = async () => {
    if (running || waitingEngine) return;
    if (engineBacked) {
      // A fresh re-attack must be executed by the engine — never simulated
      // in the browser. Queue the request and wait for the verdict.
      setRunning(true);
      setWaitingEngine(true);
      setRetestLog([
        `[panel] queueing authorized re-attack for ${finding.id}`,
        "[panel] waiting for engine…",
      ]);
      try {
        await queueRevalidation();
        setRetestLog((prev) => [
          ...prev,
          "[panel] revalidate request queued — the engine will post the verdict",
        ]);
      } catch {
        setRunning(false);
        setWaitingEngine(false);
        setRetestLog(["[panel] failed to queue re-validation — try again"]);
        toast.error("Could not queue re-validation", {
          description: "The revalidate request was rejected.",
        });
      }
      return;
    }
    // Seed findings: replay the verdict recorded in the imported data.
    setRunning(true);
    timerRef.current = window.setTimeout(() => {
      const result = runReTest(finding, state.code);
      setRetestLog(result.log);
      setRunning(false);
      setState((prev) => ({
        ...prev,
        verification: result.fixed ? "verified" : "vulnerable",
        history: [
          ...prev.history,
          {
            at: Date.now(),
            source: prev.fixSource ?? "manual",
            summary: result.fixed
              ? "Re-test passed — attack path exhausted"
              : "Re-test failed — attack still succeeds",
            fixed: result.fixed,
          },
        ],
      }));
      if (result.fixed) {
        toast.success("VERIFIED FIXED", {
          description:
            result.source === "engine"
              ? `Every recorded attack step is blocked — verdict from the orchestrator run.`
              : `${finding.id} no longer responds to the authorized attack.`,
        });
      } else {
        toast.error("STILL VULNERABLE", {
          description:
            result.source === "engine"
              ? "The validator reproduced the attack on the current code."
              : "The validator reproduced the attack. Update the code and re-test.",
        });
      }
    }, 1400);
  };

  const openProposal = () => {
    setFixProposal(true);
  };

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-xs text-muted-foreground">{finding.id}</span>
            <Badge
              variant="outline"
              className={cn("font-mono text-[10px] uppercase tracking-wider", SEVERITY_STYLES[finding.severity])}
            >
              {finding.severity}
            </Badge>
            <Badge
              variant="outline"
              className={cn("font-mono text-[10px]", VERIFICATION_META[state.verification].styles)}
            >
              {(() => {
                const Icon = VERIFICATION_META[state.verification].icon;
                return <Icon className="mr-1 size-3" />;
              })()}
              {VERIFICATION_META[state.verification].label}
            </Badge>
            {waitingEngine && (
              <Badge
                variant="outline"
                className="border-cyan-400/30 bg-cyan-400/10 font-mono text-[10px] text-cyan-300"
              >
                <Clock className="mr-1 size-3" />
                Waiting for engine
              </Badge>
            )}
            {approvalPending && !waitingEngine && (
              <Badge
                variant="outline"
                className="border-amber-400/30 bg-amber-400/10 font-mono text-[10px] text-amber-300"
              >
                Approval queued
              </Badge>
            )}
          </div>
          <h1 className="mt-2 text-xl font-semibold tracking-tight text-foreground sm:text-2xl">
            {finding.title}
          </h1>
          <p className="mt-1 font-mono text-xs text-muted-foreground">
            {finding.repo} / {finding.file} · {finding.location}
          </p>
        </div>

        {/* Loop steps */}
        <ol className="flex flex-wrap items-center gap-1.5">
          {STEP_LABELS.map((step, i) => {
            const done = i + 1 < currentStep;
            const active = i + 1 === currentStep;
            return (
              <li key={step} className="flex items-center gap-1.5">
                <span
                  className={cn(
                    "rounded-full border px-2.5 py-1 font-mono text-[10px]",
                    done && "border-emerald-400/25 bg-emerald-400/10 text-emerald-300",
                    active && "border-violet-400/40 bg-violet-500/15 text-violet-200",
                    !done && !active && "border-white/10 bg-white/[0.02] text-muted-foreground",
                  )}
                >
                  {done ? "✓ " : `${i + 1}. `}
                  {step}
                </span>
                {i < STEP_LABELS.length - 1 && <span className="text-white/20">›</span>}
              </li>
            );
          })}
        </ol>
      </div>

      {/* Detail + evidence */}
      <div className="grid gap-4 lg:grid-cols-5">
        <div className="space-y-4 lg:col-span-2">
          <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4">
            <h3 className="flex items-center gap-2 text-xs font-medium uppercase tracking-[0.12em] text-muted-foreground">
              <Target className="size-3.5 text-violet-300" />
              What was tested
            </h3>
            <Separator className="my-3 opacity-50" />
            <div className="text-sm leading-relaxed text-foreground/85">
              {finding.explanation}
            </div>
            <Separator className="my-3 opacity-50" />
            <div>
              <p className="mb-1.5 font-mono text-[10px] uppercase tracking-[0.14em] text-muted-foreground">
                Attack path
              </p>
              <ol className="space-y-1.5">
                {finding.attackPath.map((step, i) => (
                  <li key={i} className="flex gap-2 text-xs text-muted-foreground">
                    <span className="shrink-0 font-mono text-violet-300/80">{i + 1}.</span>
                    {step}
                  </li>
                ))}
              </ol>
            </div>
            <Separator className="my-3 opacity-50" />
            <div>
              <MetaRow label="Type" value={finding.vulnerabilityType} />
              <MetaRow label="Surface" value={finding.attackSurface} />
              <MetaRow label="Location" value={`${finding.file} · ${finding.location}`} />
            </div>
            <Separator className="my-3 opacity-50" />
            <div className="rounded-lg border border-violet-400/20 bg-violet-500/[0.06] p-3 text-xs leading-relaxed text-violet-100/85">
              <p className="mb-1 font-medium text-violet-200">Recommended remediation</p>
              {finding.remediation}
            </div>
          </div>
        </div>
        <div className="lg:col-span-3">
          <EvidenceViewer finding={finding} />
        </div>
      </div>

      {/* Workspace */}
      <Tabs defaultValue="editor" className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <TabsList className="bg-white/[0.03]">
            <TabsTrigger value="editor" className="gap-1.5">
              <Pencil className="size-3.5" />
              Code workspace
            </TabsTrigger>
            <TabsTrigger value="diff" className="gap-1.5">
              <GitCompare className="size-3.5" />
              Diff vs original
            </TabsTrigger>
          </TabsList>

          <div className="flex flex-wrap items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              disabled={!hasEdits}
              onClick={() => {
                setSavedCode(state.code);
                setState((prev) => ({
                  ...prev,
                  verification: "unverified",
                  fixSource: null,
                }));
                if (engineBacked) {
                  // Manual edits go through the same approval gate so the
                  // engine applies the buffer, re-attacks, and records the
                  // real verdict.
                  void submitApproval("manual", state.code);
                  toast.success("Manual edits saved", {
                    description:
                      "Approval queued — the engine will apply the buffer and re-attack.",
                  });
                } else {
                  toast.success("Manual edits saved", {
                    description: "Run the re-test to verify the fix.",
                  });
                }
              }}
            >
              <Save className="size-3.5" />
              Save manual edits
            </Button>
            <Button
              size="sm"
              onClick={openProposal}
              className="bg-violet-600 text-white shadow-[0_0_20px_rgba(124,58,237,0.35)] hover:bg-violet-500"
            >
              <Sparkles className="size-3.5" />
              Fix with PurpleGuard AI
            </Button>
          </div>
        </div>

        <TabsContent value="editor" className="mt-0">
          <CodeEditor
            code={state.code}
            onChange={(next) => setState((prev) => ({ ...prev, code: next }))}
            disabled={running}
          />
        </TabsContent>
        <TabsContent value="diff" className="mt-0">
          <DiffView oldCode={finding.vulnerableCode} newCode={state.code} />
        </TabsContent>
      </Tabs>

      {/* Re-test */}
      <ReTestPanel
        state={state}
        finding={finding}
        log={retestLog}
        running={running}
        waiting={waitingEngine}
        engineBacked={engineBacked}
        onRun={handleReTest}
      />

      {/* History */}
      {state.history.length > 0 && (
        <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4">
          <button
            type="button"
            onClick={() => setHistoryOpen((o) => !o)}
            className="flex w-full items-center justify-between font-mono text-[11px] uppercase tracking-[0.14em] text-muted-foreground"
          >
            <span className="flex items-center gap-2">
              <Terminal className="size-3.5" />
              Loop history · {state.history.length} events · {state.attempts} attempts
            </span>
            <span>{historyOpen ? "hide" : "show"}</span>
          </button>
          <AnimatePresence initial={false}>
            {historyOpen && (
              <motion.ul
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: "auto", opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                className="overflow-hidden"
              >
                {[...state.history].reverse().map((entry, i) => (
                  <li
                    key={`${entry.at}-${i}`}
                    className="flex items-center gap-3 border-t border-white/[0.04] py-2 font-mono text-[11px]"
                  >
                    <span className={entry.fixed ? "text-emerald-300" : "text-amber-300"}>
                      {entry.fixed ? "pass" : "pending"}
                    </span>
                    <span className="text-violet-300/80">{entry.source}</span>
                    <span className="min-w-0 flex-1 truncate text-muted-foreground">
                      {entry.summary}
                    </span>
                  </li>
                ))}
              </motion.ul>
            )}
          </AnimatePresence>
        </div>
      )}

      {/* AI fix proposal dialog */}
      <Dialog open={fixProposal} onOpenChange={setFixProposal}>
        <DialogContent className="max-w-3xl border-white/10 bg-[oklch(0.16_0.012_288)]">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-base">
              <Sparkles className="size-4 text-violet-300" />
              Proposed fix · {finding.id}
            </DialogTitle>
            <DialogDescription>
              Review the patch below. Nothing changes until you explicitly approve.
            </DialogDescription>
          </DialogHeader>

          <div className="max-h-[55vh] overflow-y-auto pr-1">
            {proposalMatchesWorkspace ? (
              <>
                <p className="mb-3 flex items-center gap-2 text-xs text-muted-foreground">
                  <Code2 className="size-3.5" />
                  Your workspace already matches the proposal — approving is a no-op.
                </p>
                <DiffView oldCode={finding.vulnerableCode} newCode={finding.proposedPatch} />
              </>
            ) : (
              <>
                <div className="mb-2 flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.14em] text-muted-foreground">
                  <span className="flex-1">Current workspace</span>
                  <span className="text-violet-300">ECC proposal</span>
                </div>
                <DiffView oldCode={state.code} newCode={finding.proposedPatch} />
              </>
            )}

            <div className="mt-4 space-y-2 rounded-lg border border-violet-400/20 bg-violet-500/[0.06] p-3.5 text-xs leading-relaxed text-violet-100/85">
              <p className="font-medium text-violet-200">Why this fix works</p>
              <p>{finding.remediation}</p>
              <p className="text-violet-200/70">
                ECC will verify by re-running the authorized attack path after the patch
                is applied.
              </p>
            </div>
          </div>

          <DialogFooter className="gap-2">
            <Button variant="outline" onClick={() => setFixProposal(false)}>
              <Ban className="size-3.5" />
              Reject
            </Button>
            <Button
              onClick={() => setApplyConfirm(true)}
              disabled={proposalMatchesWorkspace}
              className="bg-violet-600 text-white hover:bg-violet-500"
            >
              <Check className="size-3.5" />
              Approve &amp; apply
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Explicit apply confirmation */}
      <Dialog open={applyConfirm} onOpenChange={setApplyConfirm}>
        <DialogContent className="max-w-md border-white/10 bg-[oklch(0.16_0.012_288)]">
          <DialogHeader>
            <DialogTitle className="text-base">Apply ECC patch?</DialogTitle>
            <DialogDescription>
              The proposed modification will replace the workspace code for{" "}
              {finding.file}. A re-test will be queued immediately after.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setApplyConfirm(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => applyFix("ai")}
              className="bg-emerald-600 text-white hover:bg-emerald-500"
            >
              <Check className="size-3.5" />
              Yes, apply patch
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
