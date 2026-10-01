import {
  ArrowRight,
  Boxes,
  Check,
  ExternalLink,
  FolderGit2,
  LayoutDashboard,
  Loader2,
  Lock,
  ShieldAlert,
  ShieldCheck,
  Target,
  X,
} from "lucide-react";
import { useEffect, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router";
import { useMutation } from "convex/react";
import { toast } from "sonner";
import { api } from "@/convex/_generated/api";
import { ScoreRing } from "@/components/landing/console";
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
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useGithubConnection } from "@/hooks/useGithubConnection";
import { usePurpleGuardData } from "@/hooks/usePurpleGuardData";
import { useProjectSelection } from "@/hooks/useProjectSelection";
import { cn } from "@/lib/utils";

/* ------------------------------------------------------------------ */
/* Connect Project dialog                                              */
/* ------------------------------------------------------------------ */

const OTHER_SOURCES = [
  { id: "gitlab", label: "GitLab", hint: "GitLab.com or self-managed" },
  { id: "bitbucket", label: "Bitbucket", hint: "Bitbucket Cloud" },
  { id: "local", label: "Local Project", hint: "Point the engine at a local checkout" },
  { id: "upload", label: "Upload Project", hint: "Upload an archive for one-off validation" },
] as const;

/** Honest source labels — never present a connector as live when it isn't. */
const SOURCE_META: Record<string, { label: string; className: string }> = {
  github: { label: "GitHub", className: "border-violet-400/25 bg-violet-500/10 text-violet-200" },
  engine: { label: "engine", className: "border-cyan-400/25 bg-cyan-400/10 text-cyan-300" },
  handoff: { label: "handoff", className: "border-amber-400/25 bg-amber-400/10 text-amber-300" },
  manual: { label: "manual", className: "border-white/10 bg-white/[0.03] text-muted-foreground" },
};

function ConnectProjectDialog({
  open,
  onOpenChange,
  onProjectAdded,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onProjectAdded: (repo: string) => void;
}) {
  const gh = useGithubConnection();
  const addManual = useMutation(api.projects.addManual);
  const connectGithub = useMutation(api.projects.connectGithub);
  const [picked, setPicked] = useState<string | null>(null);
  const [registering, setRegistering] = useState(false);
  const [connecting, setConnecting] = useState(false);
  const [manualValue, setManualValue] = useState("");

  // Reset local state whenever the dialog reopens — derive from the open
  // prop via key reset instead of setState-in-effect.
  useEffect(() => {
    if (!open) return;
    const task = setTimeout(() => {
      setPicked(null);
      setManualValue("");
    }, 0);
    return () => clearTimeout(task);
  }, [open]);

  const registerPicked = async () => {
    if (!picked) return;
    setRegistering(true);
    try {
      const repoMeta = gh.repos.find((r) => r.fullName === picked);
      await connectGithub({
        repo: picked,
        externalId: repoMeta?.id,
        private: repoMeta?.private,
      });
      toast.success(`${picked} connected`, {
        description:
          "PurpleGuard now tracks this project. Start validation from the Hacker panel.",
      });
      onProjectAdded(picked);
      onOpenChange(false);
    } catch (e) {
      toast.error("Could not connect repository", {
        description: e instanceof Error ? e.message : "Unknown error",
      });
    } finally {
      setRegistering(false);
    }
  };

  const registerManual = async () => {
    const repo = manualValue.trim();
    if (!repo) return;
    setRegistering(true);
    try {
      await addManual({ repo });
      toast.success(`${repo} added`, {
        description: "Registered manually. A real connector (GitHub OAuth) upgrades the source later.",
      });
      onProjectAdded(repo);
      onOpenChange(false);
    } catch (e) {
      toast.error("Could not add project", {
        description: e instanceof Error ? e.message : "Unknown error",
      });
    } finally {
      setRegistering(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg border-white/10 bg-[oklch(0.16_0.012_288)]">
        <DialogHeader>
          <DialogTitle>Connect your project</DialogTitle>
          <DialogDescription>
            Connect a source PurpleGuard can validate. GitHub uses OAuth when
            the deployment's GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET keys are
            set; any project can also be registered by identifier right now,
            and a later GitHub connection upgrades it.
          </DialogDescription>
        </DialogHeader>

        {/* Step 1 — pick source */}
        <div className="space-y-2">
          <button
            type="button"
            onClick={() => {
              if (gh.connected || registering || connecting) return;
              setConnecting(true);
              void gh
                .connect()
                .catch((e: unknown) => {
                  toast.error("Could not start GitHub connect", {
                    description:
                      e instanceof Error
                        ? e.message
                        : "Sign in and try again — the connect must start from a signed-in session.",
                  });
                })
                .finally(() => setConnecting(false));
            }}
            disabled={registering || connecting}
            className={cn(
              "flex w-full items-center gap-3 rounded-xl border p-4 text-left transition-colors",
              gh.connected
                ? "border-violet-400/25 bg-violet-500/[0.06]"
                : "border-violet-400/25 bg-violet-500/[0.06] hover:bg-violet-500/[0.12]",
            )}
          >
            <span className="flex size-10 items-center justify-center rounded-lg border border-white/10 bg-white/[0.03] text-violet-300">
              <FolderGit2 className="size-5" />
            </span>
            <span className="min-w-0 flex-1">
              <span className="block text-sm font-medium text-foreground">
                GitHub
                {gh.connected && gh.login && (
                  <span className="ml-2 font-mono text-[10px] text-violet-300">
                    connected as {gh.login}
                  </span>
                )}
              </span>
              <span className="block truncate text-xs text-muted-foreground">
                {gh.connected
                  ? "Pick one of your repositories below"
                  : "Authorize PurpleGuard via GitHub OAuth"}
              </span>
            </span>
            {!gh.connected && !connecting && (
              <span className="hidden shrink-0 rounded-full border border-white/10 bg-white/[0.03] px-2 py-0.5 font-mono text-[10px] text-muted-foreground sm:block">
                needs OAuth keys
              </span>
            )}
            {!gh.connected && (
              <span className="flex shrink-0 items-center gap-2">
                {connecting && <Loader2 className="size-4 animate-spin text-violet-300" />}
                <ArrowRight className="size-4 text-violet-300" />
              </span>
            )}
          </button>

          {gh.loading && (
            <p className="flex items-center gap-2 px-1 font-mono text-[10px] text-muted-foreground">
              <Loader2 className="size-3 animate-spin" /> checking GitHub connection…
            </p>
          )}

          {/* Step 2 — repo picker (only when connected) */}
          {gh.connected && (
            <div className="rounded-xl border border-white/[0.06] bg-black/20">
              <div className="flex items-center justify-between border-b border-white/[0.06] px-3.5 py-2">
                <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-muted-foreground">
                  your repositories
                </span>
              </div>
              <ScrollArea className="max-h-56">
                <ul className="p-1.5">
                  {gh.repos.map((r) => (
                    <li key={r.id}>
                      <button
                        type="button"
                        onClick={() => setPicked(r.fullName)}
                        className={cn(
                          "flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-left transition-colors",
                          picked === r.fullName
                            ? "bg-violet-500/15 text-foreground"
                            : "text-foreground/85 hover:bg-white/[0.04]",
                        )}
                      >
                        {r.private ? (
                          <Lock className="size-3.5 shrink-0 text-muted-foreground" />
                        ) : (
                          <FolderGit2 className="size-3.5 shrink-0 text-muted-foreground" />
                        )}
                        <span className="min-w-0 flex-1 truncate font-mono text-xs">
                          {r.fullName}
                        </span>
                        {picked === r.fullName && (
                          <Check className="size-3.5 shrink-0 text-violet-300" />
                        )}
                      </button>
                    </li>
                  ))}
                  {gh.repos.length === 0 && !gh.reposError && (
                    <li className="px-2.5 py-4 text-center text-xs text-muted-foreground">
                      No accessible repositories found.
                    </li>
                  )}
                  {gh.reposError && (
                    <li className="px-2.5 py-3 text-center text-xs text-amber-300">
                      {gh.reposError}
                    </li>
                  )}
                </ul>
              </ScrollArea>
            </div>
          )}

          {picked && (
            <div className="flex items-center justify-between gap-2 rounded-lg border border-violet-400/25 bg-violet-500/[0.08] px-3 py-2.5">
              <span className="min-w-0 truncate font-mono text-xs text-foreground">
                {picked}
              </span>
              <div className="flex shrink-0 items-center gap-2">
                <a
                  href={`https://github.com/${picked}`}
                  target="_blank"
                  rel="noreferrer"
                  className="text-muted-foreground transition-colors hover:text-foreground"
                  aria-label="Open on GitHub"
                >
                  <ExternalLink className="size-3.5" />
                </a>
                <Button
                  size="sm"
                  disabled={registering}
                  onClick={() => void registerPicked()}
                  className="bg-violet-600 text-white hover:bg-violet-500"
                >
                  {registering ? <Loader2 className="size-3.5 animate-spin" /> : <Check className="size-3.5" />}
                  Connect
                </Button>
              </div>
            </div>
          )}

          {/* Other sources — honest "soon" state */}
          <div className="border-t border-white/[0.06] pt-2">
            {OTHER_SOURCES.map((s) => (
              <button
                key={s.id}
                type="button"
                disabled
                className="flex w-full cursor-not-allowed items-center gap-3 rounded-xl border border-white/[0.06] bg-white/[0.01] p-3 text-left opacity-60"
              >
                <span className="flex size-8 items-center justify-center rounded-lg border border-white/10 bg-white/[0.03] text-muted-foreground">
                  <FolderGit2 className="size-4" />
                </span>
                <span className="min-w-0 flex-1">
                  <span className="block text-sm font-medium text-foreground">{s.label}</span>
                  <span className="block truncate text-xs text-muted-foreground">{s.hint}</span>
                </span>
                <span className="rounded-full border border-white/10 bg-white/[0.03] px-2 py-0.5 font-mono text-[10px] text-muted-foreground">
                  soon
                </span>
              </button>
            ))}
          </div>
        </div>

        <DialogFooter className="sm:justify-between">
          <div className="flex min-w-0 flex-1 items-center gap-2">
            <Input
              value={manualValue}
              onChange={(e) => setManualValue(e.target.value)}
              placeholder="or add identifier manually…"
              className="h-8 border-white/10 bg-white/[0.02] font-mono text-xs"
              onKeyDown={(e) => {
                if (e.key === "Enter" && manualValue.trim()) void registerManual();
              }}
            />
            <Button
              variant="outline"
              size="sm"
              disabled={!manualValue.trim() || registering}
              onClick={() => void registerManual()}
            >
              Add
            </Button>
          </div>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            Close
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/* ------------------------------------------------------------------ */
/* Page                                                                */
/* ------------------------------------------------------------------ */

export default function Dashboard() {
  const { loading, projects, totals, activity } = usePurpleGuardData();
  const { setProjectId } = useProjectSelection();
  const gh = useGithubConnection();
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const [connectOpen, setConnectOpen] = useState(false);
  // Reopen-trigger for the connect dialog: set by the OAuth ?github=connected
  // return, consumed by the effect below. Keeps state updates out of effects.
  const [connectNonce, setConnectNonce] = useState(0);

  const today = new Date().toLocaleDateString("en-US", {
    weekday: "long",
    month: "long",
    day: "numeric",
  });
  const hour = new Date().getHours();
  const greeting =
    hour < 5
      ? "Good night"
      : hour < 12
        ? "Good morning"
        : hour < 18
          ? "Good afternoon"
          : "Good evening";  // GitHub OAuth callback lands on /dashboard?github=connected|error=…
  // Toasts and the URL cleanup run in a task; opening the dialog is the
  // reset-key's job (avoids setState-in-effect).
  useEffect(() => {
    const ghParam = params.get("github");
    if (!ghParam) return;
    if (ghParam === "connected") {
      toast.success("GitHub connected", {
        description: "Pick a repository to register it as a PurpleGuard project.",
      });
    } else if (ghParam.startsWith("error=")) {
      toast.error("GitHub connection failed", {
        description: ghParam.slice("error=".length),
      });
    }
    const task = setTimeout(() => {
      params.delete("github");
      setParams(params, { replace: true });
      setConnectOpen(true); // continue straight into the repo picker
      setConnectNonce((n) => n + 1); // re-run the dialog's reset pass
    }, 0);
    return () => clearTimeout(task);

    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <PanelShell panel="console" badge="Command Center">
      <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        {/* Greeting */}
        <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
          <div>
            <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted-foreground">
              {today} · authorized validation engine
            </p>
            <h1 className="mt-1 text-2xl font-semibold tracking-tight text-foreground sm:text-3xl">
              {greeting}. Your security overview.
            </h1>
          </div>
          <Button
            onClick={() => setConnectOpen(true)}
            className="bg-violet-600 text-white shadow-[0_0_24px_rgba(124,58,237,0.4)] hover:bg-violet-500"
          >
            <Boxes className="size-4" />
            + Connect Project
          </Button>
        </div>

        {/* KPI strip */}
        <div className="mt-8 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <div className="flex items-center justify-center gap-4 rounded-xl border border-white/[0.06] bg-white/[0.02] p-4">
            <ScoreRing score={totals.verifiedPct} size={96} strokeWidth={6} />
            <div className="min-w-0">
              <p className="text-[11px] font-medium uppercase tracking-[0.12em] text-muted-foreground">
                Verified
              </p>
              <p className="font-mono text-sm text-foreground">
                {totals.verified} of {totals.total} findings
              </p>
              <p className="mt-1 font-mono text-[10px] text-muted-foreground">
                {totals.critical} critical · {totals.high} high
              </p>
            </div>
          </div>
          <KpiTile label="Projects" value={String(projects.length)} icon={FolderGit2} />
          <KpiTile label="Critical" value={String(totals.critical)} icon={ShieldAlert} />
          <KpiTile label="High" value={String(totals.high)} icon={Target} />
        </div>

        {/* Projects */}
        <div className="mt-8 flex items-center justify-between">
          <h2 className="text-sm font-medium uppercase tracking-[0.12em] text-muted-foreground">
            Projects
          </h2>
          <span className="font-mono text-[10px] text-muted-foreground">
            from findings · first-class connections persisted
          </span>
        </div>
        <div className="mt-3 grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {projects.map((p) => {
            const meta = SOURCE_META[p.source] ?? SOURCE_META.manual;
            return (
              <div
                key={p.id}
                className="group rounded-xl border border-white/[0.06] bg-white/[0.02] p-5 transition-colors hover:border-violet-400/25"
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <button
                      type="button"
                      onClick={() => {
                        setProjectId(p.id);
                        navigate(`/dashboard/projects/${encodeURIComponent(p.id)}`);
                      }}
                      className="truncate text-sm font-semibold tracking-tight text-foreground hover:text-violet-200"
                    >
                      {p.name}
                    </button>
                    <p className="mt-0.5 font-mono text-[10px] text-muted-foreground">
                      {p.total} finding{p.total === 1 ? "" : "s"}
                    </p>
                  </div>
                  <Badge
                    variant="outline"
                    className={cn("shrink-0 font-mono text-[10px]", meta.className)}
                  >
                    {meta.label}
                  </Badge>
                </div>
                <div className="mt-4 flex flex-wrap items-center gap-3 font-mono text-[10px]">
                  <span className="flex items-center gap-1.5 text-rose-300">
                    <span className="size-1.5 rounded-full bg-rose-400" />
                    {p.critical} critical
                  </span>
                  <span className="flex items-center gap-1.5 text-amber-300">
                    <span className="size-1.5 rounded-full bg-amber-400" />
                    {p.high} high
                  </span>
                  <span className="flex items-center gap-1.5 text-emerald-300">
                    <span className="size-1.5 rounded-full bg-emerald-400" />
                    {p.verified} verified
                  </span>
                </div>
                <div className="mt-4 flex items-center gap-2">
                  <Link
                    to={`/dashboard/projects/${encodeURIComponent(p.id)}`}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-white/10 bg-white/[0.03] px-3 py-1.5 text-xs font-medium text-foreground transition-colors hover:bg-white/[0.06]"
                  >
                    Open Project
                  </Link>
                  <Link
                    to={`/hacker?project=${encodeURIComponent(p.id)}`}
                    className="inline-flex items-center gap-1.5 rounded-lg bg-violet-600 px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-violet-500"
                  >
                    Validate
                  </Link>
                </div>
              </div>
            );
          })}
          {projects.length === 0 && !loading && (
            <div className="col-span-full rounded-xl border border-dashed border-white/10 p-8 text-center text-sm text-muted-foreground">
              No projects yet — connect one to start validation.
            </div>
          )}
        </div>

        {/* Activity + routing */}
        <div className="mt-8 grid gap-4 lg:grid-cols-3">
          <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-5 lg:col-span-2">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-medium uppercase tracking-[0.12em] text-muted-foreground">
                Recent security activity
              </h2>
              <Link
                to="/hacker"
                className="inline-flex items-center gap-1.5 font-mono text-[10px] text-violet-300 hover:text-violet-200"
              >
                Hacker panel
                <ArrowRight className="size-3" />
              </Link>
            </div>
            <ul className="mt-3 space-y-1">
              {activity.map((a) => (
                <li
                  key={a.id}
                  className="flex items-center gap-2.5 rounded-lg px-2 py-2 font-mono text-[11px] transition-colors hover:bg-white/[0.02]"
                >
                  <span
                    className={cn(
                      "size-1.5 shrink-0 rounded-full",
                      a.tone === "emerald" && "bg-emerald-400",
                      a.tone === "rose" && "bg-rose-400",
                      a.tone === "amber" && "bg-amber-400",
                      a.tone === "cyan" && "bg-cyan-400",
                      a.tone === "violet" && "bg-violet-400",
                    )}
                    aria-hidden
                  />
                  <span className="min-w-0 flex-1 truncate text-foreground/85">
                    {a.text}
                  </span>
                </li>
              ))}
              {activity.length === 0 && (
                <li className="px-2 py-4 text-sm text-muted-foreground">
                  No activity yet — connect a project and run validation.
                </li>
              )}
            </ul>
          </div>

          <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-5">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-medium uppercase tracking-[0.12em] text-muted-foreground">
                Go deeper
              </h2>
              {gh.connected && gh.login && (
                <button
                  type="button"
                  onClick={() =>
                    void gh.disconnect().then(() =>
                      toast.success("GitHub disconnected"),
                    )
                  }
                  className="inline-flex items-center gap-1 font-mono text-[10px] text-muted-foreground transition-colors hover:text-rose-300"
                >
                  <X className="size-3" />
                  disconnect {gh.login}
                </button>
              )}
            </div>
            <div className="mt-3 space-y-2">
              <PanelLink
                to="/hacker"
                icon={Target}
                title="Hacker — validation"
                desc="Prove what can actually be attacked."
              />
              <PanelLink
                to="/developer"
                icon={ShieldCheck}
                title="Developer — workspace"
                desc="Understand, fix, and verify the code."
              />
              <PanelLink
                to="/ecc"
                icon={LayoutDashboard}
                title="ECC — orchestration"
                desc="Watch the machinery underneath."
              />
            </div>
          </div>
        </div>
      </div>

      <ConnectProjectDialog
        key={connectNonce}
        open={connectOpen}
        onOpenChange={setConnectOpen}
        onProjectAdded={(repo) => {
          setProjectId(repo);
          navigate(`/dashboard/projects/${encodeURIComponent(repo)}`);
        }}
      />
    </PanelShell>
  );
}

/* ------------------------------------------------------------------ */
/* Small widgets                                                       */
/* ------------------------------------------------------------------ */

function KpiTile({
  label,
  value,
  icon: Icon,
}: {
  label: string;
  value: string;
  icon: typeof FolderGit2;
}) {
  return (
    <div className="flex items-center gap-3.5 rounded-xl border border-white/[0.06] bg-white/[0.02] p-4 transition-colors hover:border-violet-400/20">
      <span className="flex size-9 shrink-0 items-center justify-center rounded-lg border border-white/10 bg-white/[0.03] text-violet-300">
        <Icon className="size-4" />
      </span>
      <div className="min-w-0">
        <p className="truncate text-[11px] font-medium uppercase tracking-[0.12em] text-muted-foreground">
          {label}
        </p>
        <p className="font-mono text-xl font-semibold tracking-tight text-foreground">
          {value}
        </p>
      </div>
    </div>
  );
}

function PanelLink({
  to,
  icon: Icon,
  title,
  desc,
}: {
  to: string;
  icon: typeof FolderGit2;
  title: string;
  desc: string;
}) {
  return (
    <Link
      to={to}
      className="flex items-start gap-3 rounded-lg border border-white/[0.06] bg-white/[0.01] p-3 transition-colors hover:border-violet-400/25 hover:bg-white/[0.03]"
    >
      <span className="flex size-8 shrink-0 items-center justify-center rounded-lg border border-white/10 bg-white/[0.03] text-violet-300">
        <Icon className="size-4" />
      </span>
      <span className="min-w-0">
        <span className="block text-sm font-medium text-foreground">{title}</span>
        <span className="block text-xs text-muted-foreground">{desc}</span>
      </span>
    </Link>
  );
}
