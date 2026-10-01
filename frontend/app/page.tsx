"use client";

import { useEffect, useMemo, useState } from "react";

const API_URL =
  process.env.NEXT_PUBLIC_PURPLEGUARD_API || "";

type Finding = {
  id: string;
  name: string;
  title?: string;
  category: string;
  severity: string;
  file: string;
  line: number;
  code?: string;
  description?: string;
  source_file?: string;
  source_line?: number;
  source_name?: string;
  sink_file?: string;
  sink_line?: number;
  sink_name?: string;
  payload?: string;
  evidence?: string;
  impact?: string;
  validator?: string;
  validated?: boolean;
};

type SecureResult = {
  status?: string;
  message?: string;
  project?: string;
  recon?: {
    files_analyzed?: number;
    attack_surfaces?: number;
    attack_paths?: number;
  };
  plans?: Array<{
    path_id: string;
    category: string;
    severity: string;
    confidence: number;
    validator: string;
  }>;
  validation?: Array<{
    path_id: string;
    category: string;
    severity?: string;
    validator?: string;
    payload?: string;
    evidence?: string;
    validated?: boolean;
    attack?: string;
    request?: unknown;
  }>;
  confirmed_attacks?: number;
  findings?: Finding[];
  remediation?: {
    previews?: {
      finding_id: string;
      path_id: string;
      rule_id: string;
      category: string;
      severity: string;
      file: string;
      line: number;
      vulnerable_code: string;
      proposed_code: string;
      recommendation: string;
      explanation: string;
      patch: string;
      patch_file?: string | null;
      status: string;
      source_available: boolean;
    }[];
    available?: number;
    approved?: boolean;
    result?: {
      results?: Array<{
        status?: string;
        file?: string;
        finding_id?: string;
        message?: string;
      }>;
    };
  };
  verification?: {
    static_scan?: {
      passed?: boolean;
      remaining_count?: number;
    };
    tests?: {
      passed?: boolean;
      tests_passed?: boolean;
      return_code?: number | null;
      output?: string;
      errors?: string;
    };
    hacker?: {
      status?: string;
      all_attacks_blocked?: boolean;
      results?: Array<{
        finding_id?: string;
        path_id?: string;
        category?: string;
        severity?: string;
        payload?: string;
        validated?: boolean;
        blocked?: boolean;
        status?: string;
        evidence?: string;
      }>;
    };
    verdict?: {
      status?: string;
      static_scan_passed?: boolean;
      tests_passed?: boolean;
      hacker_verification_passed?: boolean;
      all_checks_passed?: boolean;
    };
  };
};

const navigation = [
  { name: "Overview", icon: "⌂", group: "Console" },
  { name: "Hacker", icon: "◈", group: "Project" },
  { name: "Developer", icon: "⌘", group: "Project" },
  { name: "Scanner", icon: "⌕", group: "Project" },
  { name: "AI Engineer", icon: "✦", group: "Project" },
  { name: "ECC / Security Workforce", icon: "⬡", group: "Project" },
  { name: "Findings", icon: "!", group: "Workflow" },
  { name: "Attack", icon: "⚔", group: "Workflow" },
  { name: "Changes", icon: "↗", group: "Workflow" },
  { name: "Verification", icon: "✓", group: "Workflow" },
  { name: "History", icon: "◷", group: "Workflow" },
];

function severityClass(severity: string) {
  if (severity === "CRITICAL") {
    return "bg-red-400/10 text-red-300";
  }

  if (severity === "HIGH") {
    return "bg-orange-400/10 text-orange-300";
  }

  if (severity === "MEDIUM") {
    return "bg-yellow-400/10 text-yellow-300";
  }

  return "bg-blue-400/10 text-blue-300";
}

function displayFile(path: string) {
  const parts = path.split("/");
  return parts[parts.length - 1] || path;
}

function boolLabel(value: boolean | undefined) {
  return value ? "PASSED" : "FAILED";
}

function normalizeFinding(raw: any): Finding {
  return {
    id: raw.id || raw.finding_id || "UNKNOWN",
    name:
      raw.name ||
      raw.title ||
      raw.category ||
      "Security Finding",
    title: raw.title,
    category: raw.category || "UNKNOWN",
    severity: raw.severity || "UNKNOWN",
    file:
      raw.file ||
      raw.source_file ||
      raw.sink_file ||
      "Unknown file",
    line:
      raw.line ||
      raw.source_line ||
      raw.sink_line ||
      0,
    code: raw.code,
    description: raw.description,
    source_file: raw.source_file,
    source_line: raw.source_line,
    source_name: raw.source_name,
    sink_file: raw.sink_file,
    sink_line: raw.sink_line,
    sink_name: raw.sink_name,
    payload: raw.payload,
    evidence: raw.evidence,
    impact: raw.impact,
    validator: raw.validator,
    validated: raw.validated,
  };
}

export default function Home() {
  const [view, setView] = useState<"landing" | "console">("landing");
  const [active, setActive] = useState("Overview");

  const [connected, setConnected] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [securing, setSecuring] = useState(false);

  const [scanError, setScanError] = useState("");
  const [secureError, setSecureError] = useState("");

  const [selectedFinding, setSelectedFinding] =
    useState<Finding | null>(null);

  const [target, setTarget] = useState(
    "tests/hacker_target_web"
  );

  const [findings, setFindings] = useState<Finding[]>([]);
  const [lastScanTarget, setLastScanTarget] = useState("");
  const [secureResult, setSecureResult] =
    useState<SecureResult | null>(null);

  const [selectedAttackPath, setSelectedAttackPath] =
    useState<string | null>(null);

  const [backendStatus, setBackendStatus] = useState<
    "checking" | "online" | "offline"
  >("checking");

  async function checkBackend() {
    try {
      const response = await fetch(`${API_URL}/status`);
      setBackendStatus(response.ok ? "online" : "offline");
    } catch {
      setBackendStatus("offline");
    }
  }

  useEffect(() => {
    // Real backend health check against the live API.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    checkBackend();
  }, []);

  async function runScan() {
    if (scanning || securing) {
      return;
    }

    if (!target.trim()) {
      setScanError("Enter a project path first.");
      return;
    }

    setScanning(true);
    setScanError("");

    try {
      const response = await fetch(`${API_URL}/scan`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          target: target.trim(),
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.error || "PurpleGuard could not scan the project."
        );
      }

      setFindings((data.findings || []).map(normalizeFinding));
      setLastScanTarget(data.target || target.trim());
      setConnected(true);
    } catch (error) {
      setScanError(
        error instanceof Error
          ? error.message
          : "Unable to connect to PurpleGuard API."
      );

      // A failed scan must not leave stale successful results on screen.
      setFindings([]);
      setSecureResult(null);
      setLastScanTarget("");
      setConnected(false);
    } finally {
      setScanning(false);
    }
  }

  async function runPurpleGuard(approved = false) {
    if (securing || scanning) {
      return;
    }

    if (!target.trim()) {
      setSecureError("Enter a project path first.");
      return;
    }

    setSecuring(true);
    setSecureError("");

    try {
      const response = await fetch(`${API_URL}/secure`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          target: target.trim(),
          approved,
        }),
      });

      const data: SecureResult = await response.json();

      if (!response.ok) {
        throw new Error(
          (data as SecureResult & { error?: string }).error ||
            "PurpleGuard security operation failed."
        );
      }

      setSecureResult(data);
      setConnected(true);
      setLastScanTarget(data.project || target.trim());

      if (data.findings) {
        setFindings(data.findings.map(normalizeFinding));
      }

      setActive(approved ? "Verification" : "Attack");
    setSelectedAttackPath(null);
    } catch (error) {
      setSecureError(
        error instanceof Error
          ? error.message
          : "Unable to connect to PurpleGuard."
      );

      // A failed operation must not leave a stale verdict on screen.
      setSecureResult(null);
    } finally {
      setSecuring(false);
    }
  }

  const [resetting, setResetting] = useState(false);

  async function resetFixture() {
    if (resetting) {
      return;
    }

    setResetting(true);
    try {
      const res = await fetch(`${API_URL}/reset`, { method: "POST" });
      const data = await res.json();
      if (data.status === "ok") {
        setSecureResult(null);
        setFindings([]);
        setConnected(false);
        setLastScanTarget("");
        setActive("Overview");
        setScanError("");
        setSecureError("");
        setSelectedAttackPath(null);
        setSelectedFinding(null);
      }
    } catch {
      /* ignore */
    } finally {
      setResetting(false);
    }
  }

  const criticalCount = useMemo(
    () =>
      findings.filter(
        (finding) => finding.severity === "CRITICAL"
      ).length,
    [findings]
  );

  const highCount = useMemo(
    () =>
      findings.filter(
        (finding) => finding.severity === "HIGH"
      ).length,
    [findings]
  );

  const mediumCount = useMemo(
    () =>
      findings.filter(
        (finding) => finding.severity === "MEDIUM"
      ).length,
    [findings]
  );

  const securityScore = useMemo(() => {
    if (findings.length === 0) return 100;

    const deductions = findings.reduce((total, finding) => {
      if (finding.severity === "CRITICAL") return total + 20;
      if (finding.severity === "HIGH") return total + 12;
      if (finding.severity === "MEDIUM") return total + 6;
      return total + 2;
    }, 0);

    return Math.max(0, 100 - deductions);
  }, [findings]);

  const riskLabel =
    findings.length === 0
      ? "No known issues"
      : criticalCount > 0
        ? "Critical risk"
        : highCount > 0
          ? "High risk"
          : mediumCount > 0
            ? "Moderate risk"
            : "Low risk";

  if (view === "landing") {
    return <LandingScreen onEnter={() => setView("console")} />;
  }

  return (
    <main className="min-h-screen bg-[#08070c] text-white">
      <header className="sticky top-0 z-50 border-b border-white/10 bg-[#08070c]/90 backdrop-blur-xl">
        <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 md:px-8">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-purple-500 font-black">
              P
            </div>

            <div>
              <div className="font-semibold tracking-tight">
                PurpleGuard
              </div>

              <div className="text-[10px] uppercase tracking-[0.2em] text-white/40">
                AI Security Engineer
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setView("landing")}
              className="hidden rounded-full border border-white/10 px-3 py-1.5 text-xs text-white/50 transition hover:bg-white/5 hover:text-white sm:block"
            >
              ← Landing
            </button>

            <div
              className={`hidden items-center gap-2 rounded-full border px-3 py-1.5 text-xs sm:flex ${
                backendStatus === "offline"
                  ? "border-red-400/20 bg-red-400/5 text-red-300"
                  : backendStatus === "online"
                    ? "border-emerald-400/20 bg-emerald-400/5 text-emerald-300"
                    : "border-white/10 bg-white/5 text-white/50"
              }`}
            >
              <span
                className={`h-1.5 w-1.5 rounded-full ${
                  backendStatus === "offline"
                    ? "bg-red-400"
                    : backendStatus === "online"
                      ? "bg-emerald-400"
                      : "bg-white/40"
                }`}
              />
              {backendStatus === "offline"
                ? "Engine offline"
                : backendStatus === "online"
                  ? connected
                    ? "Engine connected"
                    : "Engine online"
                  : "Connecting…"}
            </div>
          </div>
        </div>
      </header>

      <div className="mx-auto flex max-w-7xl">
        <aside className="hidden w-60 shrink-0 border-r border-white/10 px-4 py-6 lg:block">
          <nav className="space-y-1">
            {navigation.map((item, index) => (
              <div key={item.name}>
                {(index === 0 || navigation[index - 1].group !== item.group) && (
                  <div
                    className={`px-3 text-[10px] font-semibold uppercase tracking-[0.2em] text-white/30 ${
                      index === 0 ? "mb-2" : "mb-2 mt-5"
                    }`}
                  >
                    {item.group}
                  </div>
                )}

                <button
                  onClick={() => setActive(item.name)}
                  className={`flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-sm transition ${
                    active === item.name
                      ? "bg-purple-500/15 text-white ring-1 ring-purple-500/20"
                      : "text-white/50 hover:bg-white/5 hover:text-white"
                  }`}
                >
                  <span className="flex w-5 justify-center">
                    {item.icon}
                  </span>
                  {item.name}
                </button>
              </div>
            ))}
          </nav>

          <div className="mt-8 rounded-2xl border border-white/10 bg-white/[0.025] p-4">
            <div className="mb-2 text-xs font-medium text-white/40">
              TARGET
            </div>

            <div className="truncate text-sm font-medium">
              {connected
                ? displayFile(lastScanTarget)
                : "No target analyzed"}
            </div>

            <div className="mt-1 truncate text-xs text-white/35">
              {connected ? "local · connected" : "waiting"}
            </div>
          </div>
        </aside>

        <section className="min-w-0 flex-1 px-4 py-5 pb-24 lg:px-8 lg:py-10 lg:pb-10">
          <div className="mb-5 flex gap-2 overflow-x-auto pb-1 lg:hidden">
            {navigation.map((item) => (
              <button
                key={item.name}
                onClick={() => setActive(item.name)}
                className={`shrink-0 rounded-full px-3 py-2 text-xs ${
                  active === item.name
                    ? "bg-purple-500 text-white"
                    : "bg-white/5 text-white/50"
                }`}
              >
                {item.name}
              </button>
            ))}
          </div>

          <div className="mb-8 flex flex-col justify-between gap-5 lg:flex-row lg:items-end">
            <div>
              <div className="mb-3 flex items-center gap-2 text-xs text-white/40">
                <span>PurpleGuard</span>
                <span>/</span>
                <span className="text-white/70">{active}</span>
              </div>

              <h1 className="text-3xl font-semibold tracking-tight md:text-4xl">
                {active === "Attack"
                  ? "Think like an attacker. Prove the risk."
                  : "Security that understands your code."}
              </h1>

              <p className="mt-3 max-w-2xl text-sm leading-6 text-white/45 md:text-base">
                PurpleGuard analyzes code, discovers attack paths,
                safely validates authorized targets, proposes remediation,
                and verifies the result.
              </p>
            </div>

          </div>

          <div className="mb-6 overflow-hidden rounded-3xl border border-purple-500/20 bg-gradient-to-br from-purple-500/[0.09] via-white/[0.025] to-transparent shadow-2xl shadow-purple-950/20 p-5 md:p-7">
            <div className="mb-4">
              <div className="text-lg font-semibold">
                Authorized security target
              </div>

              <p className="mt-1 text-sm text-white/40">
                Enter a project that you are authorized to analyze.
              </p>
            </div>

            <div className="flex flex-col gap-3 md:flex-row">
              <input
                value={target}
                onChange={(event) =>
                  setTarget(event.target.value)
                }
                className="min-w-0 flex-1 rounded-xl border border-white/10 bg-black/30 px-4 py-3 font-mono text-xs text-white outline-none focus:border-purple-400/50"
                placeholder="/path/to/project"
              />

              <div className="flex gap-2">
                <button
                  onClick={() => runPurpleGuard(false)}
                  disabled={securing}
                  className="rounded-xl bg-purple-500 px-5 py-3 text-sm font-semibold disabled:opacity-60"
                >
                  {securing ? "Analyzing..." : "Analyze with PurpleGuard"}
                </button>

                <button
                  onClick={resetFixture}
                  disabled={resetting}
                  className="rounded-xl border border-white/10 bg-white/5 px-4 py-3 text-xs font-medium text-white/50 transition hover:bg-white/10 hover:text-white disabled:opacity-40"
                >
                  {resetting ? "Resetting..." : "Reset Fixture"}
                </button>
              </div>
            </div>

            {scanError && (
              <div className="mt-4 rounded-xl border border-red-400/20 bg-red-400/5 px-4 py-3 text-xs text-red-300">
                {scanError}
              </div>
            )}

            {secureError && (
              <div className="mt-4 rounded-xl border border-red-400/20 bg-red-400/5 px-4 py-3 text-xs text-red-300">
                {secureError}
              </div>
            )}

            {lastScanTarget && !secureError && (
              <div className="mt-4 text-xs text-emerald-300">
                ● Target connected · {lastScanTarget}
              </div>
            )}

            {lastScanTarget &&
              !scanError &&
              !secureError &&
              findings.length === 0 &&
              !securing &&
              !scanning && (
                <div className="mt-3 rounded-xl border border-sky-400/20 bg-sky-400/5 px-4 py-3 text-xs leading-5 text-sky-200/90">
                  Target analyzed — the engine found no vulnerable
                  patterns in the current source.
                  {lastScanTarget.includes("hacker_target") && (
                    <>
                      {" "}
                      The bundled demo fixture is currently in a
                      <strong> safe state (guarded or already
                      remediated)</strong>. Press
                      <strong> Reset Fixture</strong> to load the
                      vulnerable demo target, then run the analysis
                      again to see confirmed findings.
                    </>
                  )}
                </div>
              )}

            {secureResult?.verification && (
              <div
                className={`mt-3 flex flex-wrap items-center gap-x-5 gap-y-2 rounded-xl border px-4 py-3 text-xs ${
                  secureResult.verification.verdict?.status ===
                  "SECURITY_VERIFIED"
                    ? "border-emerald-400/20 bg-emerald-400/5 text-emerald-200"
                    : "border-amber-400/20 bg-amber-400/5 text-amber-200"
                }`}
              >
                <span className="font-semibold">
                  {secureResult.verification.verdict?.status ||
                    "NO VERDICT RETURNED"}
                </span>

                <span>
                  Rescan:{" "}
                  {secureResult.verification.static_scan
                    ?.remaining_count ?? "unknown"}{" "}
                  findings remaining
                </span>

                <span>
                  Re-attack:{" "}
                  {
                    (
                      secureResult.verification.hacker?.results || []
                    ).filter((item) => item.blocked === true).length
                  }
                  /
                  {(
                    secureResult.verification.hacker?.results || []
                  ).length}{" "}
                  blocked
                </span>

                <span>
                  Tests:{" "}
                  {secureResult.verification.tests?.passed === true
                    ? "PASSED"
                    : "FAILED"}
                </span>
              </div>
            )}
          </div>

          {active === "Overview" && (
            <>
              <div className="grid gap-4 md:grid-cols-3">
                <div className="rounded-3xl border border-white/10 bg-white/[0.025] p-6">
                  <div className="text-xs uppercase tracking-wider text-white/35">
                    Security score
                  </div>

                  <div className="mt-5 text-5xl font-semibold">
                    {securityScore}
                    <span className="ml-2 text-sm text-white/30">
                      / 100
                    </span>
                  </div>

                  <div className="mt-5 h-1.5 overflow-hidden rounded-full bg-white/10">
                    <div
                      className="h-full rounded-full bg-purple-500 transition-all"
                      style={{
                        width: `${securityScore}%`,
                      }}
                    />
                  </div>

                  <div className="mt-3 text-xs text-orange-300">
                    {riskLabel}
                  </div>
                </div>

                <div className="rounded-3xl border border-white/10 bg-white/[0.025] p-6">
                  <div className="text-xs uppercase tracking-wider text-white/35">
                    Findings
                  </div>

                  <div className="mt-5 text-5xl font-semibold">
                    {findings.length}
                  </div>

                  <div className="mt-4 flex flex-wrap gap-2 text-xs">
                    {criticalCount > 0 && (
                      <span className="rounded-full bg-red-400/10 px-2.5 py-1 text-red-300">
                        {criticalCount} Critical
                      </span>
                    )}

                    {highCount > 0 && (
                      <span className="rounded-full bg-orange-400/10 px-2.5 py-1 text-orange-300">
                        {highCount} High
                      </span>
                    )}

                    {mediumCount > 0 && (
                      <span className="rounded-full bg-yellow-400/10 px-2.5 py-1 text-yellow-300">
                        {mediumCount} Medium
                      </span>
                    )}

                    {findings.length === 0 && (
                      <span className="text-emerald-300">
                        Clean
                      </span>
                    )}
                  </div>
                </div>

                <div className="rounded-3xl border border-white/10 bg-white/[0.025] p-6">
                  <div className="text-xs uppercase tracking-wider text-white/35">
                    Security engine
                  </div>

                  <div className="mt-5 text-xl font-semibold">
                    {secureResult?.status ||
                      "Ready"}
                  </div>

                  <div className="mt-2 text-xs leading-5 text-white/35">
                    {secureResult?.message ||
                      "PurpleGuard is ready to investigate the authorized target."}
                  </div>
                </div>
              </div>
            </>
          )}

          {active === "Scanner" && (
            <div className="rounded-3xl border border-white/10 bg-white/[0.025] p-6">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <h2 className="text-xl font-semibold">
                    Static scanner
                  </h2>

                  <p className="mt-1 text-sm text-white/40">
                    Runs the real PurpleGuard static analysis engine
                    (PG001–PG012) against the current target.
                  </p>
                </div>

                <button
                  onClick={runScan}
                  disabled={scanning}
                  className="rounded-xl bg-purple-500 px-4 py-2.5 text-xs font-semibold disabled:opacity-50"
                >
                  {scanning ? "Scanning..." : "Run static scan"}
                </button>
              </div>

              {scanError && (
                <div className="mt-4 rounded-xl border border-red-400/20 bg-red-400/5 px-4 py-3 text-xs text-red-300">
                  {scanError}
                </div>
              )}

              <div className="mt-6 flex items-center gap-2 text-xs text-white/40">
                <span className="h-1.5 w-1.5 rounded-full bg-purple-400" />
                {findings.length} finding(s) returned by the engine
                {lastScanTarget ? ` · ${lastScanTarget}` : ""}
              </div>

              {findings.length === 0 ? (
                <div className="mt-5 rounded-2xl border border-white/10 bg-black/20 p-6 text-sm text-white/40">
                  No findings loaded. Point the target at an authorized
                  project and press “Run static scan”.
                </div>
              ) : (
                <div className="mt-5 space-y-3">
                  {findings.map((finding) => (
                    <button
                      key={`${finding.id}-${finding.file}-${finding.line}`}
                      onClick={() => setSelectedFinding(finding)}
                      className="w-full rounded-2xl border border-white/10 p-4 text-left transition hover:bg-white/5"
                    >
                      <div className="flex flex-wrap items-center gap-3">
                        <span
                          className={`rounded-full px-2.5 py-1 text-[10px] font-semibold ${severityClass(
                            finding.severity
                          )}`}
                        >
                          {finding.severity}
                        </span>

                        <span className="text-xs text-purple-300">
                          {finding.id}
                        </span>

                        <span className="text-sm font-semibold">
                          {displayFile(finding.file)}:{finding.line}
                        </span>
                      </div>

                      <div className="mt-2 text-xs text-white/45">
                        {finding.title ||
                          finding.name ||
                          finding.category}
                      </div>

                      {finding.code && (
                        <code className="mt-2 block truncate rounded-lg bg-black/40 p-2 font-mono text-[11px] text-purple-200">
                          {finding.code}
                        </code>
                      )}
                    </button>
                  ))}
                </div>
              )}
            </div>
          )}

          {active === "Attack" && (
            <div className="space-y-6">
              <div className="rounded-3xl border border-purple-500/20 bg-purple-500/5 p-6">
                <div className="text-xs font-semibold uppercase tracking-[0.18em] text-purple-300">
                  Authorized Attack Mode
                </div>

                <h2 className="mt-2 text-2xl font-semibold">
                  PurpleGuard is investigating the target.
                </h2>

                <p className="mt-2 max-w-2xl text-sm leading-6 text-white/40">
                  PurpleGuard first discovers possible attack paths and
                  then uses controlled validation against the authorized
                  local target. A discovered path is not treated as
                  confirmed until validation produces evidence.
                </p>
              </div>

              {secureResult ? (
                <>
                  <div className="grid gap-4 sm:grid-cols-3">
                    <Metric
                      label="Files analyzed"
                      value={
                        secureResult.recon?.files_analyzed ?? 0
                      }
                    />

                    <Metric
                      label="Attack surfaces"
                      value={
                        secureResult.recon?.attack_surfaces ?? 0
                      }
                    />

                    <Metric
                      label="Attack paths"
                      value={
                        secureResult.recon?.attack_paths ?? 0
                      }
                    />
                  </div>

                  <div className="rounded-3xl border border-white/10 bg-white/[0.025] p-6">
                    <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
                      <div>
                        <div className="text-xs font-semibold uppercase tracking-[0.16em] text-purple-300">
                          Attack intelligence
                        </div>

                        <h2 className="mt-2 text-xl font-semibold">
                          Attack paths discovered
                        </h2>

                        <p className="mt-1 text-xs text-white/35">
                          PurpleGuard separates suspected attack paths from
                          attacks that have been behaviorally validated.
                        </p>
                      </div>

                      <div className="text-sm text-white/40">
                        {(secureResult.plans || []).length} discovered
                        {" · "}
                        {secureResult.confirmed_attacks ?? 0} validated
                        {" · "}
                        {
                          (secureResult.verification?.hacker?.results || [])
                            .filter((item) => item.blocked === true).length
                        }{" "}
                        blocked
                      </div>
                    </div>

                    <div className="mt-5 space-y-3">
                      {(secureResult.plans || []).map((plan) => {
                        const validation = (
                          secureResult.validation || []
                        ).find(
                          (item) => item.path_id === plan.path_id
                        );

                        const retest = (
                          secureResult.verification?.hacker?.results || []
                        ).find(
                          (item) => item.path_id === plan.path_id
                        );

                        return (
                          <AttackPathCard
                            key={plan.path_id}
                            plan={plan}
                            validation={validation}
                            retest={retest}
                            remediation={(
                              secureResult.remediation?.previews || []
                            ).find(
                              (item) => item.path_id === plan.path_id
                            )}
                            onApprove={runPurpleGuard}
                            securing={securing}
                            selected={
                              selectedAttackPath === plan.path_id
                            }
                            onSelect={() =>
                              setSelectedAttackPath(
                                selectedAttackPath === plan.path_id
                                  ? null
                                  : plan.path_id
                              )
                            }
                          />
                        );
                      })}

                      {(!secureResult.plans ||
                        secureResult.plans.length === 0) && (
                        <div className="rounded-2xl border border-white/10 p-5 text-sm text-white/35">
                          No attack paths were discovered.
                        </div>
                      )}
                    </div>
                  </div>

                  <div className="rounded-3xl border border-white/10 bg-white/[0.025] p-6">
                    <div className="flex items-center justify-between">
                      <div>
                        <h2 className="text-lg font-semibold">
                          Validation
                        </h2>

                        <p className="mt-1 text-xs text-white/35">
                          Controlled evidence from the authorized target.
                        </p>
                      </div>

                      <div className="text-sm font-semibold">
                        {secureResult.confirmed_attacks ?? 0} confirmed
                      </div>
                    </div>

                    <div className="mt-5 space-y-3">
                      {(secureResult.validation || []).map(
                        (validation, index) => (
                          <div
                            key={
                              validation.path_id || index
                            }
                            className="rounded-2xl border border-white/10 bg-black/20 p-4"
                          >
                            <div className="flex flex-wrap items-center gap-2">
                              <span className="text-sm font-semibold">
                                {validation.category}
                              </span>

                              {validation.severity && (
                                <span
                                  className={`rounded-full px-2 py-1 text-[9px] font-semibold ${severityClass(
                                    validation.severity
                                  )}`}
                                >
                                  {validation.severity}
                                </span>
                              )}

                              <span
                                className={`ml-auto rounded-full px-2 py-1 text-[9px] ${
                                  validation.validated
                                    ? "bg-red-400/10 text-red-300"
                                    : "bg-emerald-400/10 text-emerald-300"
                                }`}
                              >
                                {validation.validated
                                  ? "CONFIRMED"
                                  : "NOT CONFIRMED"}
                              </span>
                            </div>

                            <div className="mt-3">
                              <div className="text-[10px] uppercase tracking-wider text-white/30">
                                Controlled payload
                              </div>

                              <code className="mt-1 block rounded-lg bg-black/40 p-3 font-mono text-xs text-purple-200">
                                {validation.payload || "—"}
                              </code>
                            </div>

                            <div className="mt-3">
                              <div className="text-[10px] uppercase tracking-wider text-white/30">
                                Evidence
                              </div>

                              <div className="mt-1 text-sm leading-6 text-white/55">
                                {validation.evidence || "—"}
                              </div>
                            </div>
                          </div>
                        )
                      )}

                      {(!secureResult.validation ||
                        secureResult.validation.length === 0) && (
                        <div className="rounded-2xl border border-white/10 p-5 text-sm text-white/40">
                          No validation results were produced.
                        </div>
                      )}
                    </div>
                  </div>

                  {secureResult.status ===
                    "APPROVAL_REQUIRED" && (
                    <div className="rounded-3xl border border-orange-400/20 bg-orange-400/5 p-6">
                      <div className="text-xs uppercase tracking-wider text-orange-300">
                        Developer approval required
                      </div>

                      <h2 className="mt-2 text-xl font-semibold">
                        Fixes are available.
                      </h2>

                      <p className="mt-2 text-sm text-white/40">
                        PurpleGuard will not modify source code until
                        you explicitly approve the remediation.
                      </p>

                      <button
                        onClick={() => runPurpleGuard(true)}
                        disabled={securing}
                        className="mt-5 rounded-xl bg-orange-400 px-5 py-3 text-sm font-semibold text-black disabled:opacity-50"
                      >
                        {securing
                          ? "Applying and verifying..."
                          : "Approve & Apply Fixes"}
                      </button>
                    </div>
                  )}
                </>
              ) : (
                <div className="rounded-3xl border border-white/10 bg-white/[0.025] p-10 text-center">
                  <div className="text-xl font-semibold">
                    Attack engine ready
                  </div>

                  <p className="mx-auto mt-2 max-w-lg text-sm leading-6 text-white/35">
                    Run PurpleGuard to discover and safely validate
                    attack paths against the selected authorized target.
                  </p>

                  <button
                    onClick={() => runPurpleGuard(false)}
                    disabled={securing}
                    className="mt-6 rounded-xl bg-purple-500 px-5 py-3 text-sm font-semibold disabled:opacity-50"
                  >
                    {securing
                      ? "Investigating..."
                      : "Start Attack Investigation"}
                  </button>
                </div>
              )}
            </div>
          )}

          {active === "Hacker" && (
            <WorkforcePanel target={target} apiUrl={API_URL} />
          )}

          {active === "Developer" && (
            <DeveloperPanel target={target} apiUrl={API_URL} />
          )}

          {active === "ECC / Security Workforce" && (
            <EccWorkforcePanel apiUrl={API_URL} />
          )}

          {active === "Findings" && (
            <FindingsPanel
              findings={findings}
              result={secureResult}
              onSelect={setSelectedFinding}
            />
          )}

          {active === "AI Engineer" && (
            <AIEngineerPanel
              findings={findings}
              result={secureResult}
              onSelect={setSelectedFinding}
              onApprove={runPurpleGuard}
              securing={securing}
            />
          )}

          {active === "Changes" && (
            <ChangesPanel result={secureResult} />
          )}

          {active === "Verification" && (
            <VerificationPanel result={secureResult} />
          )}

          {active === "History" && (
            <HistoryPanel apiUrl={API_URL} result={secureResult} />
          )}

          <footer className="mt-12 border-t border-white/10 py-6 text-xs text-white/25">
            PurpleGuard AI · Security engineering engine · v0.1
          </footer>
        </section>
      </div>

      {selectedFinding && (
        <div
          className="fixed inset-0 z-[100] flex items-center justify-center bg-black/80 p-4 backdrop-blur-sm"
          onClick={() => setSelectedFinding(null)}
        >
          <div
            className="max-h-[92vh] w-full max-w-4xl overflow-y-auto rounded-3xl border border-white/10 bg-[#100e16] shadow-2xl"
            onClick={(event) => event.stopPropagation()}
          >
            {(() => {
              const preview =
                secureResult?.remediation?.previews?.find(
                  (item) =>
                    item.finding_id === selectedFinding.id ||
                    item.category === selectedFinding.category
                );

              const confirmed = selectedFinding.validated === true;

              return (
                <>
                  <div className="border-b border-white/10 p-6">
                    <div className="flex items-start justify-between gap-4">
                      <div className="min-w-0">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="text-xs text-purple-300">
                            {selectedFinding.id}
                          </span>

                          <span
                            className={`rounded-full px-2.5 py-1 text-[10px] ${severityClass(
                              selectedFinding.severity
                            )}`}
                          >
                            {selectedFinding.severity}
                          </span>

                          <span
                            className={`rounded-full border px-2.5 py-1 text-[10px] uppercase tracking-wider ${
                              confirmed
                                ? "border-emerald-400/20 bg-emerald-400/10 text-emerald-300"
                                : "border-white/10 bg-white/5 text-white/40"
                            }`}
                          >
                            {confirmed ? "CONFIRMED" : "DETECTED"}
                          </span>
                        </div>

                        <h2 className="mt-3 text-2xl font-semibold">
                          {selectedFinding.title ||
                            selectedFinding.name ||
                            selectedFinding.category}
                        </h2>

                        <p className="mt-2 text-sm text-white/40">
                          {selectedFinding.category}
                        </p>
                      </div>

                      <button
                        onClick={() => setSelectedFinding(null)}
                        className="shrink-0 rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-sm text-white/50 transition hover:bg-white/10 hover:text-white"
                      >
                        Close
                      </button>
                    </div>
                  </div>

                  <div className="space-y-6 p-6">

                    <div
                      className={`rounded-2xl border p-5 ${
                        confirmed
                          ? "border-emerald-400/20 bg-emerald-400/[0.05]"
                          : "border-white/10 bg-white/[0.025]"
                      }`}
                    >
                      <div className="flex items-start gap-4">
                        <div
                          className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-xl ${
                            confirmed
                              ? "bg-emerald-400/10 text-emerald-300"
                              : "bg-white/5 text-white/40"
                          }`}
                        >
                          {confirmed ? "✓" : "!"}
                        </div>

                        <div>
                          <div className="text-sm font-semibold">
                            {confirmed
                              ? "PurpleGuard confirmed this vulnerability"
                              : "PurpleGuard detected a potential vulnerability"}
                          </div>

                          <p className="mt-1 text-xs leading-5 text-white/40">
                            {confirmed
                              ? "The security weakness was behaviourally validated against the authorised target."
                              : "This finding has been identified by static analysis but has not yet received behavioural confirmation."}
                          </p>
                        </div>
                      </div>
                    </div>

                    <div>
                      <div className="mb-3 text-xs uppercase tracking-[0.18em] text-white/30">
                        Attack path
                      </div>

                      <div className="grid gap-3 md:grid-cols-3">
                        <InfoBlock
                          label="Source"
                          value={
                            selectedFinding.source_file
                              ? `${displayFile(
                                  selectedFinding.source_file
                                )}:${selectedFinding.source_line ?? "?"}`
                              : `${displayFile(
                                  selectedFinding.file
                                )}:${selectedFinding.line}`
                          }
                        />

                        <InfoBlock
                          label="Data flow"
                          value={
                            selectedFinding.source_name ||
                            "User-controlled input"
                          }
                        />

                        <InfoBlock
                          label="Sink"
                          value={
                            selectedFinding.sink_file
                              ? `${displayFile(
                                  selectedFinding.sink_file
                                )}:${selectedFinding.sink_line ?? "?"}`
                              : selectedFinding.sink_name ||
                                "Security-sensitive operation"
                          }
                        />
                      </div>
                    </div>

                    <div>
                      <div className="mb-3 text-xs uppercase tracking-[0.18em] text-white/30">
                        Behavioural proof
                      </div>

                      <div className="space-y-3">
                        {selectedFinding.payload && (
                          <DetailSection
                            label="Controlled validation payload"
                            value={selectedFinding.payload}
                            code
                          />
                        )}

                        {selectedFinding.evidence && (
                          <DetailSection
                            label="Evidence"
                            value={selectedFinding.evidence}
                          />
                        )}

                        {selectedFinding.validator && (
                          <DetailSection
                            label="Validator"
                            value={selectedFinding.validator}
                          />
                        )}
                      </div>
                    </div>

                    {(selectedFinding.code ||
                      selectedFinding.impact ||
                      selectedFinding.description) && (
                      <div>
                        <div className="mb-3 text-xs uppercase tracking-[0.18em] text-white/30">
                          Finding analysis
                        </div>

                        <div className="space-y-3">
                          {selectedFinding.code && (
                            <DetailSection
                              label="Vulnerable code"
                              value={selectedFinding.code}
                              code
                            />
                          )}

                          {selectedFinding.impact && (
                            <DetailSection
                              label="Potential impact"
                              value={selectedFinding.impact}
                            />
                          )}

                          {selectedFinding.description &&
                            !selectedFinding.impact && (
                              <DetailSection
                                label="Description"
                                value={selectedFinding.description}
                              />
                            )}
                        </div>
                      </div>
                    )}

                    {preview && (
                      <div className="rounded-3xl border border-purple-400/20 bg-purple-400/[0.04] p-5">
                        <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                          <div>
                            <div className="text-xs uppercase tracking-[0.18em] text-purple-300/70">
                              Remediation
                            </div>

                            <h3 className="mt-2 text-lg font-semibold">
                              Proposed secure implementation
                            </h3>

                            <p className="mt-1 text-xs leading-5 text-white/40">
                              {preview.recommendation}
                            </p>
                          </div>

                          <span className="shrink-0 rounded-full border border-purple-400/20 bg-purple-400/10 px-3 py-1 text-[10px] uppercase tracking-wider text-purple-300">
                            {preview.rule_id}
                          </span>
                        </div>

                        <div className="mt-5 grid gap-4 md:grid-cols-2">
                          <CodePanel
                            label="Vulnerable code"
                            code={preview.vulnerable_code}
                          />

                          <CodePanel
                            label="Proposed secure code"
                            code={preview.proposed_code}
                            positive
                          />
                        </div>

                        <div className="mt-4 rounded-2xl border border-white/10 bg-black/10 p-4">
                          <div className="text-[10px] uppercase tracking-wider text-white/25">
                            Why this fix works
                          </div>

                          <p className="mt-2 text-xs leading-5 text-white/45">
                            {preview.explanation}
                          </p>
                        </div>

                        {preview.patch && (
                          <div className="mt-4">
                            <DetailSection
                              label="Full patch"
                              value={preview.patch}
                              code
                            />
                          </div>
                        )}

                        <div className="mt-5 flex flex-col gap-3 rounded-2xl border border-amber-400/10 bg-amber-400/[0.03] p-4 sm:flex-row sm:items-center sm:justify-between">
                          <div>
                            <div className="text-xs font-medium text-amber-200/80">
                              Approval required
                            </div>

                            <p className="mt-1 text-[11px] leading-5 text-white/35">
                              PurpleGuard will not modify the project until
                              the developer explicitly approves the proposed
                              remediation.
                            </p>
                          </div>

                          <button
                            type="button"
                            onClick={() => {
                              setSelectedFinding(null);
                              runPurpleGuard(true);
                            }}
                            disabled={securing}
                            className="shrink-0 rounded-xl bg-purple-500 px-4 py-2.5 text-xs font-semibold text-white transition hover:bg-purple-400 disabled:cursor-not-allowed disabled:opacity-50"
                          >
                            {securing
                              ? "Applying & Verifying..."
                              : "Approve & Apply Fix"}
                          </button>
                        </div>
                      </div>
                    )}

                    {!preview && (
                      <div className="rounded-2xl border border-white/10 bg-white/[0.025] p-5">
                        <div className="text-xs font-medium text-white/60">
                          Remediation not available
                        </div>

                        <p className="mt-1 text-xs leading-5 text-white/35">
                          PurpleGuard has not generated an applicable
                          remediation preview for this finding yet.
                        </p>
                      </div>
                    )}

                  </div>
                </>
              );
            })()}
          </div>
        </div>
      )}

    </main>
  );
}


function AttackPathCard({
  plan,
  validation,
  retest,
  remediation,
  onApprove,
  securing,
  selected,
  onSelect,
}: {
  plan: NonNullable<SecureResult["plans"]>[number];
  validation?: NonNullable<SecureResult["validation"]>[number];
  retest?: NonNullable<
    NonNullable<
      NonNullable<SecureResult["verification"]>["hacker"]
    >["results"]
  >[number];
  remediation?: NonNullable<
    NonNullable<SecureResult["remediation"]>["previews"]
  >[number];
  onApprove: (approved?: boolean) => void;
  securing: boolean;
  selected: boolean;
  onSelect: () => void;
}) {
  const confirmed = validation?.validated === true;

  // Lifecycle state comes strictly from backend evidence:
  // DISCOVERED = path found, no validation yet
  // VALIDATED  = behavioural validation confirmed the exploit
  // UNRESOLVED = re-attack after remediation still succeeds
  // BLOCKED    = re-attack after remediation was blocked
  const retested =
    retest !== undefined && retest.blocked !== undefined;
  const blocked = retest?.blocked === true;
  const pathStatus = blocked
    ? "BLOCKED"
    : retested
      ? "UNRESOLVED"
      : confirmed
        ? "VALIDATED"
        : "DISCOVERED";

  const category = plan.category.replaceAll("_", " ");

  const isSql = plan.category === "SQL_INJECTION";
  const isCodeExecution = plan.category === "CODE_EXECUTION";

  const sourceLabel = isSql
    ? "User-controlled username"
    : isCodeExecution
      ? "User-controlled expression"
      : "Attacker-controlled input";

  const flowLabel = isSql
    ? "Dynamic SQL query"
    : isCodeExecution
      ? "Python expression evaluation"
      : "Application processing";

  const sinkLabel = isSql
    ? "Database execution"
    : isCodeExecution
      ? "Code execution sink"
      : "Sensitive application sink";

  return (
    <div
      className={`overflow-hidden rounded-3xl border transition ${
        selected
          ? "border-purple-400/40 bg-purple-500/[0.06]"
          : "border-white/10 bg-white/[0.025]"
      }`}
    >
      <button
        type="button"
        onClick={onSelect}
        className="w-full p-5 text-left"
      >
        <div className="flex flex-wrap items-start gap-4">
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-base font-semibold">
                {category}
              </span>

              <span
                className={`rounded-full px-2.5 py-1 text-[9px] font-semibold ${severityClass(
                  plan.severity
                )}`}
              >
                {plan.severity}
              </span>
            </div>

            <div className="mt-2 flex flex-wrap items-center gap-2 text-xs text-white/35">
              <span>{plan.path_id}</span>
              <span>•</span>
              <span>{plan.validator}</span>
            </div>
          </div>

          <div
            className={`rounded-full px-3 py-1.5 text-[9px] font-semibold ${
              blocked
                ? "bg-emerald-400/10 text-emerald-300"
                : pathStatus === "UNRESOLVED"
                  ? "bg-amber-400/10 text-amber-300"
                  : confirmed
                    ? "bg-red-400/10 text-red-300"
                    : "bg-white/5 text-white/40"
            }`}
          >
            {blocked
              ? "✓ BLOCKED"
              : pathStatus === "UNRESOLVED"
                ? "⚠ UNRESOLVED"
                : confirmed
                  ? "VALIDATED"
                  : "DISCOVERED"}
          </div>
        </div>

        <div className="mt-6 rounded-2xl border border-white/10 bg-black/20 p-4">
          <div className="mb-4 text-[9px] font-semibold uppercase tracking-[0.16em] text-white/25">
            Attack path
          </div>

          <div className="flex flex-col gap-2 md:flex-row md:items-center">
            <PathNode
              label="SOURCE"
              value={sourceLabel}
            />

            <PathArrow />

            <PathNode
              label="DATA FLOW"
              value={flowLabel}
            />

            <PathArrow />

            <PathNode
              label="SINK"
              value={sinkLabel}
            />

            <PathArrow />

            <div
              className={`rounded-xl border px-3 py-3 md:min-w-[150px] ${
                confirmed
                  ? "border-red-400/20 bg-red-400/[0.06]"
                  : "border-white/10 bg-white/[0.02]"
              }`}
            >
              <div
                className={`text-[8px] font-semibold uppercase tracking-wider ${
                  confirmed
                    ? "text-red-300/70"
                    : "text-white/25"
                }`}
              >
                Result
              </div>

              <div
                className={`mt-1 text-xs font-semibold ${
                  blocked
                    ? "text-emerald-300"
                    : confirmed
                      ? "text-red-300"
                      : "text-white/45"
                }`}
              >
                {blocked
                  ? "EXPLOIT BLOCKED"
                  : confirmed
                    ? "EXPLOIT CONFIRMED"
                    : "Awaiting validation"}
              </div>
            </div>
          </div>
        </div>

        <div className="mt-4 grid gap-3 sm:grid-cols-3">
          <div className="rounded-2xl border border-white/10 bg-black/10 p-3">
            <div className="text-[9px] uppercase tracking-wider text-white/25">
              Confidence
            </div>

            <div className="mt-1 text-sm font-semibold">
              {Math.round(plan.confidence * 100)}%
            </div>
          </div>

          <div className="rounded-2xl border border-white/10 bg-black/10 p-3">
            <div className="text-[9px] uppercase tracking-wider text-white/25">
              Validator
            </div>

            <div className="mt-1 truncate font-mono text-xs text-white/55">
              {plan.validator}
            </div>
          </div>

          <div className="rounded-2xl border border-white/10 bg-black/10 p-3">
            <div className="text-[9px] uppercase tracking-wider text-white/25">
              Behavioural proof
            </div>

            <div
              className={`mt-1 text-sm font-semibold ${
                confirmed
                  ? "text-red-300"
                  : "text-white/40"
              }`}
            >
              {confirmed ? "PROVEN" : "PENDING"}
            </div>
          </div>
        </div>

        <div className="mt-4 text-center text-[10px] uppercase tracking-[0.16em] text-white/20">
          {selected ? "Collapse attack details" : "Open attack details"}
        </div>
      </button>

      {selected && (
        <div className="border-t border-white/10 p-5">
          <div
            className={`rounded-2xl border p-4 ${
              confirmed
                ? "border-red-400/20 bg-red-400/[0.05]"
                : "border-white/10 bg-white/[0.02]"
            }`}
          >
            <div className="flex items-start gap-3">
              <div
                className={`mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-full text-sm ${
                  confirmed
                    ? "bg-red-400/10 text-red-300"
                    : "bg-white/5 text-white/40"
                }`}
              >
                {confirmed ? "!" : "?"}
              </div>

              <div>
                <div
                  className={`text-xs font-semibold ${
                    confirmed
                      ? "text-red-300"
                      : "text-white/50"
                  }`}
                >
                  {confirmed
                    ? "PurpleGuard behaviorally confirmed this attack path."
                    : "PurpleGuard has not confirmed this attack path."}
                </div>

                <p className="mt-1 text-xs leading-5 text-white/35">
                  Discovery identifies a possible path. Validation
                  determines whether the controlled attack actually
                  changes application behaviour.
                </p>
              </div>
            </div>
          </div>

          {validation && (
            <div className="mt-6">
              <div className="text-[10px] font-semibold uppercase tracking-[0.16em] text-purple-300">
                Behavioural evidence
              </div>

              <div className="mt-1 text-xs text-white/30">
                Controlled validation performed against the authorized
                target.
              </div>

              <div className="mt-4 grid gap-4 lg:grid-cols-2">
                <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
                  <div className="text-[9px] uppercase tracking-wider text-white/25">
                    Controlled payload
                  </div>

                  <code className="mt-2 block overflow-x-auto rounded-xl bg-black/40 p-3 font-mono text-xs text-purple-200">
                    {validation.payload || "—"}
                  </code>
                </div>

                <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
                  <div className="text-[9px] uppercase tracking-wider text-white/25">
                    Validator result
                  </div>

                  <div className="mt-2 text-xs leading-5 text-white/55">
                    {validation.evidence ||
                      "No evidence returned."}
                  </div>
                </div>
              </div>
            </div>
          )}

          {remediation && (
            <div className="mt-7 border-t border-white/10 pt-6">
              <div className="rounded-2xl border border-purple-400/15 bg-purple-500/[0.04] p-5">
                <div className="flex items-start gap-3">
                  <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-purple-400/10 text-purple-300">
                    ✦
                  </div>

                  <div className="min-w-0">
                    <div className="text-[10px] font-semibold uppercase tracking-[0.16em] text-purple-300">
                      Remediation available
                    </div>

                    <h3 className="mt-2 text-base font-semibold">
                      Fix this attack path in AI Engineer
                    </h3>

                    <p className="mt-2 text-xs leading-5 text-white/40">
                      PurpleGuard generated a proposed security fix for this
                      confirmed attack. Attack mode proves the risk; AI Engineer
                      is where you review the reasoning, code change and
                      developer approval.
                    </p>

                    <div className="mt-4 flex flex-wrap items-center gap-2">
                      <span className="rounded-full bg-white/5 px-3 py-1.5 text-[9px] font-semibold text-white/45">
                        {remediation.status}
                      </span>

                      <span className="rounded-full bg-white/5 px-3 py-1.5 text-[9px] font-semibold text-white/35">
                        {remediation.file}:{remediation.line}
                      </span>
                    </div>

                    <div className="mt-4 rounded-xl border border-white/10 bg-black/20 p-3">
                      <div className="text-[9px] uppercase tracking-wider text-white/25">
                        Engineering handoff
                      </div>

                      <div className="mt-2 text-xs leading-5 text-white/50">
                        Review the vulnerable code, proposed secure code,
                        explanation, complete patch and approval controls from
                        the <span className="font-semibold text-purple-300">
                          AI Engineer
                        </span> page.
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {!remediation && confirmed && (
            <div className="mt-6 rounded-2xl border border-amber-400/10 bg-amber-400/[0.04] p-4 text-xs leading-5 text-amber-200/70">
              PurpleGuard confirmed the attack, but no remediation
              preview was returned for this finding.
            </div>
          )}

          {validation?.request !== undefined && (
            <details className="mt-5">
              <summary className="cursor-pointer text-[10px] font-semibold uppercase tracking-wider text-white/30">
                Validation request
              </summary>

              <pre className="mt-3 max-h-48 overflow-auto rounded-xl bg-black/40 p-3 font-mono text-[11px] text-white/50">
                {typeof validation.request === "string"
                  ? validation.request
                  : JSON.stringify(
                      validation.request,
                      null,
                      2
                    )}
              </pre>
            </details>
          )}
        </div>
      )}
    </div>
  );
}

function PathNode({
  label,
  value,
}: {
  label: string;
  value: string;
}) {
  return (
    <div className="flex-1 rounded-xl border border-white/10 bg-white/[0.02] px-3 py-3">
      <div className="text-[8px] font-semibold uppercase tracking-wider text-white/25">
        {label}
      </div>

      <div className="mt-1 text-xs font-medium text-white/65">
        {value}
      </div>
    </div>
  );
}

function PathArrow() {
  return (
    <div className="hidden shrink-0 text-white/20 md:block">
      →
    </div>
  );
}


function CodePanel({
  label,
  code,
  positive = false,
}: {
  label: string;
  code: string;
  positive?: boolean;
}) {
  return (
    <div
      className={`overflow-hidden rounded-2xl border ${
        positive
          ? "border-emerald-400/10 bg-emerald-400/[0.025]"
          : "border-red-400/10 bg-red-400/[0.025]"
      }`}
    >
      <div className="border-b border-white/10 px-4 py-3">
        <div className="text-[9px] font-semibold uppercase tracking-wider text-white/30">
          {label}
        </div>
      </div>

      <pre className="overflow-x-auto p-4 font-mono text-xs leading-6 text-white/65">
        {code || "—"}
      </pre>
    </div>
  );
}

function Metric({
  label,
  value,
}: {
  label: string;
  value: number;
}) {
  return (
    <div className="rounded-3xl border border-white/10 bg-white/[0.025] p-5">
      <div className="text-xs uppercase tracking-wider text-white/30">
        {label}
      </div>

      <div className="mt-3 text-3xl font-semibold">
        {value}
      </div>
    </div>
  );
}

function InfoBlock({
  label,
  value,
}: {
  label: string;
  value: string;
}) {
  return (
    <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
      <div className="text-[10px] uppercase tracking-wider text-white/30">
        {label}
      </div>

      <div className="mt-2 break-all font-mono text-xs text-white/70">
        {value}
      </div>
    </div>
  );
}

function DetailSection({
  label,
  value,
  code = false,
}: {
  label: string;
  value: string;
  code?: boolean;
}) {
  return (
    <div className="mt-5">
      <div className="text-[10px] uppercase tracking-wider text-white/30">
        {label}
      </div>

      <div
        className={`mt-2 rounded-2xl border border-white/10 bg-black/30 p-4 text-sm leading-6 text-white/60 ${
          code ? "font-mono text-xs" : ""
        }`}
      >
        {value}
      </div>
    </div>
  );
}

function FindingsPanel({
  findings,
  result,
  onSelect,
}: {
  findings: Finding[];
  result: SecureResult | null;
  onSelect: (finding: Finding) => void;
}) {
  const hackerResults = result?.verification?.hacker?.results || [];

  if (findings.length === 0 && hackerResults.length === 0) {
    return (
      <div className="rounded-3xl border border-white/10 bg-white/[0.025] p-8">
        <div className="text-xs uppercase tracking-[0.18em] text-white/30">
          PurpleGuard Findings
        </div>

        <h2 className="mt-2 text-2xl font-semibold">
          No security findings
        </h2>

        <p className="mt-2 max-w-2xl text-sm leading-6 text-white/40">
          Run PurpleGuard against an authorised project to discover and
          behaviourally validate security weaknesses.
        </p>
      </div>
    );
  }

  const confirmedCount =
    findings.filter((finding) => finding.validated === true).length ||
    result?.confirmed_attacks ||
    0;

  return (
    <div className="space-y-5">
      <div className="rounded-3xl border border-white/10 bg-white/[0.025] p-7">
        <div className="flex flex-col gap-5 md:flex-row md:items-end md:justify-between">
          <div>
            <div className="text-xs uppercase tracking-[0.18em] text-white/30">
              Security investigation
            </div>

            <h2 className="mt-2 text-2xl font-semibold">
              Confirmed vulnerabilities
            </h2>

            <p className="mt-2 max-w-2xl text-sm leading-6 text-white/40">
              PurpleGuard combines static analysis with authorised
              behavioural validation. A confirmed finding means the
              security weakness was demonstrated against the controlled
              target, not merely matched by a rule.
            </p>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="rounded-2xl border border-white/10 px-5 py-4">
              <div className="text-[10px] uppercase tracking-wider text-white/25">
                Findings
              </div>
              <div className="mt-1 text-2xl font-semibold">
                {findings.length}
              </div>
            </div>

            <div className="rounded-2xl border border-emerald-400/10 bg-emerald-400/[0.025] px-5 py-4">
              <div className="text-[10px] uppercase tracking-wider text-emerald-300/50">
                Confirmed
              </div>
              <div className="mt-1 text-2xl font-semibold text-emerald-300">
                {confirmedCount}
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="space-y-3">
        {findings.map((finding, index) => {
          const relatedAttack = hackerResults.find(
            (item) =>
              item.finding_id === finding.id ||
              item.category === finding.category
          );

          const confirmed =
            finding.validated === true ||
            relatedAttack?.validated === true;

          return (
            <button
              key={finding.id || index}
              type="button"
              onClick={() => onSelect(finding)}
              className="group w-full rounded-3xl border border-white/10 bg-white/[0.025] p-6 text-left transition hover:border-white/20 hover:bg-white/[0.04]"
            >
              <div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={`rounded-full px-2.5 py-1 text-[10px] ${severityClass(
                        finding.severity
                      )}`}
                    >
                      {finding.severity}
                    </span>

                    <span
                      className={`rounded-full border px-2.5 py-1 text-[10px] uppercase tracking-wider ${
                        confirmed
                          ? "border-emerald-400/20 bg-emerald-400/10 text-emerald-300"
                          : "border-white/10 bg-white/[0.03] text-white/40"
                      }`}
                    >
                      {confirmed ? "CONFIRMED" : "DETECTED"}
                    </span>

                    <span className="font-mono text-[10px] text-purple-300/70">
                      {finding.id}
                    </span>

                    <span className="text-[10px] text-white/25">
                      {finding.category}
                    </span>
                  </div>

                  <h3 className="mt-3 text-lg font-semibold">
                    {finding.title ||
                      finding.name ||
                      finding.category}
                  </h3>

                  <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-white/35">
                    <span>
                      {displayFile(
                        finding.source_file ||
                          finding.file ||
                          ""
                      )}
                    </span>

                    <span className="text-white/15">•</span>

                    <span>
                      line{" "}
                      {finding.source_line ||
                        finding.line ||
                        "?"}
                    </span>
                  </div>
                </div>

                <div className="flex shrink-0 items-center gap-2 text-xs text-white/30">
                  <span>Investigate</span>
                  <span className="text-white/50 transition group-hover:translate-x-1">
                    →
                  </span>
                </div>
              </div>

              <div className="mt-5 grid gap-3 md:grid-cols-3">
                <div className="rounded-2xl border border-white/10 p-4">
                  <div className="text-[10px] uppercase tracking-wider text-white/25">
                    Source
                  </div>
                  <div className="mt-2 truncate text-xs text-white/55">
                    {finding.source_name ||
                      finding.source_file ||
                      finding.file ||
                      "Unknown"}
                  </div>
                </div>

                <div className="rounded-2xl border border-white/10 p-4">
                  <div className="text-[10px] uppercase tracking-wider text-white/25">
                    Sink
                  </div>
                  <div className="mt-2 truncate text-xs text-white/55">
                    {finding.sink_name ||
                      finding.sink_file ||
                      "Unknown"}
                  </div>
                </div>

                <div className="rounded-2xl border border-white/10 p-4">
                  <div className="text-[10px] uppercase tracking-wider text-white/25">
                    Validation
                  </div>
                  <div
                    className={`mt-2 text-xs font-medium ${
                      confirmed
                        ? "text-emerald-300"
                        : "text-white/45"
                    }`}
                  >
                    {confirmed
                      ? "Behaviourally confirmed"
                      : "Static detection"}
                  </div>
                </div>
              </div>

              {(finding.evidence || relatedAttack?.evidence) && (
                <div className="mt-3 rounded-2xl border border-white/10 bg-black/10 p-4">
                  <div className="text-[10px] uppercase tracking-wider text-white/25">
                    Evidence
                  </div>

                  <p className="mt-2 text-xs leading-5 text-white/45">
                    {finding.evidence || relatedAttack?.evidence}
                  </p>
                </div>
              )}
            </button>
          );
        })}
      </div>
    </div>
  );
}


function AIEngineerPanel({
  findings,
  result,
  onSelect,
  onApprove,
  securing,
}: {
  findings: Finding[];
  result: SecureResult | null;
  onSelect: (finding: Finding) => void;
  onApprove: (approved: boolean) => void;
  securing: boolean;
}) {
  const previews = result?.remediation?.previews || [];

  const confirmedFindings = findings.filter(
    (finding) => finding.validated === true
  );

  if (!result || findings.length === 0) {
    return (
      <div className="space-y-6">
        <div className="rounded-3xl border border-purple-500/20 bg-purple-500/5 p-8">
          <div className="text-xs font-semibold uppercase tracking-[0.18em] text-purple-300">
            AI Security Engineer
          </div>

          <h2 className="mt-2 text-2xl font-semibold">
            Engineering workspace
          </h2>

          <p className="mt-3 max-w-2xl text-sm leading-6 text-white/40">
            PurpleGuard uses confirmed security findings to reason about
            the root cause, design a remediation, and prepare a safe
            code change for developer approval.
          </p>

          <div className="mt-6 rounded-2xl border border-white/10 bg-black/20 p-5">
            <div className="text-sm font-semibold">
              No engineering work is ready yet.
            </div>

            <p className="mt-1 text-xs leading-5 text-white/35">
              Run an authorized security investigation first so
              PurpleGuard can build remediation work from real findings.
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="rounded-3xl border border-purple-500/20 bg-purple-500/5 p-6">
        <div className="text-xs font-semibold uppercase tracking-[0.18em] text-purple-300">
          AI Security Engineer
        </div>

        <div className="mt-2 flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
          <div>
            <h2 className="text-2xl font-semibold">
              Understand the issue. Build the fix.
            </h2>

            <p className="mt-2 max-w-2xl text-sm leading-6 text-white/40">
              PurpleGuard turns confirmed attack paths into actionable
              engineering changes. Nothing is applied without explicit
              developer approval.
            </p>
          </div>

          <div className="flex gap-3">
            <div className="rounded-2xl border border-white/10 bg-black/20 px-4 py-3">
              <div className="text-[9px] uppercase tracking-wider text-white/25">
                Confirmed
              </div>
              <div className="mt-1 text-lg font-semibold">
                {confirmedFindings.length}
              </div>
            </div>

            <div className="rounded-2xl border border-white/10 bg-black/20 px-4 py-3">
              <div className="text-[9px] uppercase tracking-wider text-white/25">
                Fixes ready
              </div>
              <div className="mt-1 text-lg font-semibold">
                {previews.length}
              </div>
            </div>
          </div>
        </div>
      </div>

      {findings.map((finding, index) => {
        const preview = previews.find(
          (item: any) =>
            item.finding_id === finding.id ||
            item.category === finding.category
        );

        const confirmed = finding.validated === true;

        return (
          <div
            key={finding.id + finding.file + finding.line + index}
            className="rounded-3xl border border-white/10 bg-white/[0.025] overflow-hidden"
          >
            <div className="border-b border-white/10 p-6">
              <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-xs text-purple-300">
                      {finding.id}
                    </span>

                    <span
                      className={`rounded-full px-2.5 py-1 text-[10px] ${severityClass(
                        finding.severity
                      )}`}
                    >
                      {finding.severity}
                    </span>

                    <span
                      className={`rounded-full border px-2.5 py-1 text-[10px] uppercase tracking-wider ${
                        confirmed
                          ? "border-emerald-400/20 bg-emerald-400/10 text-emerald-300"
                          : "border-white/10 bg-white/5 text-white/40"
                      }`}
                    >
                      {confirmed ? "CONFIRMED" : "DETECTED"}
                    </span>
                  </div>

                  <h3 className="mt-3 text-xl font-semibold">
                    {finding.title ||
                      finding.name ||
                      finding.category}
                  </h3>

                  <p className="mt-1 text-xs text-white/35">
                    {finding.category}
                  </p>
                </div>

                <button
                  type="button"
                  onClick={() => onSelect(finding)}
                  className="rounded-xl border border-white/10 bg-white/5 px-4 py-2.5 text-xs font-semibold text-white/70 transition hover:bg-white/10 hover:text-white"
                >
                  Open investigation
                </button>
              </div>
            </div>

            <div className="grid gap-4 p-6 lg:grid-cols-3">
              <InfoBlock
                label="Root cause"
                value={
                  finding.description ||
                  "Security-sensitive operation receives attacker-controlled input."
                }
              />

              <InfoBlock
                label="Impact"
                value={
                  finding.impact ||
                  "The confirmed security weakness may allow unintended application behaviour."
                }
              />

              <InfoBlock
                label="Engineering action"
                value={
                  preview
                    ? "Remediation prepared and ready for developer review."
                    : "No automated remediation preview is available for this finding."
                }
              />
            </div>

            {preview ? (
              <div className="border-t border-white/10 p-6">
                <div className="flex flex-col gap-2">
                  <div className="text-[10px] font-semibold uppercase tracking-[0.16em] text-purple-300">
                    Proposed remediation
                  </div>

                  <h4 className="text-lg font-semibold">
                    {preview.explanation ||
                      "PurpleGuard has prepared a security-focused code change."}
                  </h4>

                  <p className="text-xs leading-5 text-white/35">
                    {preview.recommendation ||
                      "Review the proposed change before applying it to the project."}
                  </p>
                </div>

                <div className="mt-5 grid gap-4 lg:grid-cols-2">
                  <CodePanel
                    label="Vulnerable code"
                    code={preview.vulnerable_code}
                  />

                  <CodePanel
                    label="Proposed secure code"
                    code={preview.proposed_code}
                    positive
                  />
                </div>

                {preview.patch && (
                  <details className="mt-4">
                    <summary className="cursor-pointer text-xs font-semibold text-purple-300 hover:text-purple-200">
                      View complete patch
                    </summary>

                    <pre className="mt-3 max-h-80 overflow-auto rounded-2xl border border-white/10 bg-black/50 p-4 font-mono text-[11px] leading-5 text-white/55">
                      {preview.patch}
                    </pre>
                  </details>
                )}

                <div className="mt-5 rounded-2xl border border-orange-400/15 bg-orange-400/[0.04] p-4">
                  <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
                    <div>
                      <div className="text-xs font-semibold text-orange-200">
                        Developer approval required
                      </div>

                      <div className="mt-1 max-w-2xl text-[11px] leading-5 text-white/35">
                        PurpleGuard will not modify source code until
                        you explicitly approve this remediation. After
                        approval, the project is rescanned, tested and
                        re-attacked.
                      </div>
                    </div>

                    <button
                      type="button"
                      onClick={() => onApprove(true)}
                      disabled={
                        preview.status !== "READY" || securing
                      }
                      className="shrink-0 rounded-xl bg-orange-400 px-4 py-2.5 text-xs font-semibold text-black transition hover:bg-orange-300 disabled:cursor-not-allowed disabled:opacity-30"
                    >
                      {securing
                        ? "Applying & verifying..."
                        : "Approve & Apply Fix"}
                    </button>
                  </div>
                </div>
              </div>
            ) : (
              <div className="border-t border-white/10 p-6">
                <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
                  <div className="text-xs font-semibold">
                    Engineering analysis available
                  </div>

                  <p className="mt-1 text-xs leading-5 text-white/35">
                    This finding does not currently have an automated
                    remediation preview. Open the investigation for
                    the complete security evidence.
                  </p>
                </div>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}


function ChangesPanel({
  result,
}: {
  result: SecureResult | null;
}) {
  type ChangeRecord = {
    status?: string;
    file?: string;
    finding_id?: string;
    message?: string;
    findings?: string[];
    backup?: string;
    patch_file?: string;
    original_source?: string;
    updated_source?: string;
    patch?: string;
  };

  const changes =
    (result?.remediation?.result?.results || []) as ChangeRecord[];

  const applied = changes.filter(
    (change) => change.status === "APPLIED"
  );

  const failed = changes.filter(
    (change) =>
      change.status === "FAILED" ||
      change.status === "FILE_NOT_FOUND"
  );

  const noChange = changes.filter(
    (change) => change.status === "NO_CHANGE"
  );

  if (changes.length === 0) {
    return (
      <div className="space-y-5">
        <div className="rounded-3xl border border-white/10 bg-white/[0.025] p-6">
          <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-purple-300">
            Code changes
          </div>

          <h2 className="mt-2 text-2xl font-semibold">
            No changes applied yet.
          </h2>

          <p className="mt-2 max-w-2xl text-sm leading-6 text-white/40">
            PurpleGuard records approved remediation operations here,
            including the source transformation, patch and verification
            result.
          </p>
        </div>
      </div>
    );
  }

  const verificationStatus =
    result?.verification?.verdict?.status ||
    result?.status ||
    "UNKNOWN";

  const verificationPassed =
    verificationStatus === "SECURITY_VERIFIED";

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="rounded-3xl border border-white/10 bg-white/[0.025] p-6">
        <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-purple-300">
          Remediation record
        </div>

        <div className="mt-3 flex flex-wrap items-end justify-between gap-5">
          <div>
            <h2 className="text-2xl font-semibold">
              Changes applied by PurpleGuard.
            </h2>

            <p className="mt-2 max-w-2xl text-sm leading-6 text-white/40">
              Review exactly what PurpleGuard changed after developer
              approval, including the before/after source and generated
              patch.
            </p>
          </div>

          <div
            className={`rounded-2xl border px-5 py-4 ${
              applied.length > 0
                ? "border-emerald-400/20 bg-emerald-400/[0.05]"
                : failed.length > 0
                  ? "border-red-400/20 bg-red-400/[0.05]"
                  : "border-white/10 bg-white/[0.03]"
            }`}
          >
            <div className="text-[9px] font-semibold uppercase tracking-[0.16em] text-white/35">
              Operation status
            </div>

            <div
              className={`mt-1 text-lg font-semibold ${
                applied.length > 0
                  ? "text-emerald-200"
                  : failed.length > 0
                    ? "text-red-300"
                    : "text-white/60"
              }`}
            >
              {applied.length > 0
                ? "APPLIED"
                : failed.length > 0
                  ? "FAILED"
                  : noChange.length > 0
                    ? "NO_CHANGE"
                    : "UNKNOWN"}
            </div>
          </div>
        </div>
      </div>

      {/* Metrics */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <div className="rounded-2xl border border-white/10 bg-white/[0.025] p-5">
          <div className="text-[9px] font-semibold uppercase tracking-[0.16em] text-white/25">
            Files changed
          </div>
          <div className="mt-2 text-2xl font-semibold">
            {applied.length}
          </div>
          <div className="mt-1 text-[10px] text-white/30">
            Successfully modified
          </div>
        </div>

        <div className="rounded-2xl border border-white/10 bg-white/[0.025] p-5">
          <div className="text-[9px] font-semibold uppercase tracking-[0.16em] text-white/25">
            Findings fixed
          </div>
          <div className="mt-2 text-2xl font-semibold">
            {applied.reduce(
              (total, change) =>
                total +
                (Array.isArray(change.findings)
                  ? change.findings.length
                  : 0),
              0
            )}
          </div>
          <div className="mt-1 text-[10px] text-white/30">
            Security issues addressed
          </div>
        </div>

        <div className="rounded-2xl border border-white/10 bg-white/[0.025] p-5">
          <div className="text-[9px] font-semibold uppercase tracking-[0.16em] text-white/25">
            Failed
          </div>
          <div className="mt-2 text-2xl font-semibold">
            {failed.length}
          </div>
          <div className="mt-1 text-[10px] text-white/30">
            Requires investigation
          </div>
        </div>

        <div className="rounded-2xl border border-white/10 bg-white/[0.025] p-5">
          <div className="text-[9px] font-semibold uppercase tracking-[0.16em] text-white/25">
            Verification
          </div>
          <div
            className={`mt-2 text-sm font-semibold ${
              verificationPassed
                ? "text-emerald-300"
                : "text-amber-300"
            }`}
          >
            {verificationStatus}
          </div>
          <div className="mt-1 text-[10px] text-white/30">
            Final security verdict
          </div>
        </div>
      </div>

      {/* Change records */}
      <div className="space-y-4">
        {changes.map((change, index) => {
          const status = change.status || "UNKNOWN";
          const isApplied = status === "APPLIED";
          const isFailed =
            status === "FAILED" ||
            status === "FILE_NOT_FOUND";

          /*
           * The backend remediation record now contains richer fields
           * than the original frontend type. Keep the existing API
           * contract while safely reading the new engineering fields.
           */
          const record = change as typeof change & {
            findings?: string[];
            backup?: string;
            patch_file?: string;
            original_source?: string;
            updated_source?: string;
            patch?: string;
          };

          return (
            <div
              key={`${change.file || "change"}-${index}`}
              className="overflow-hidden rounded-3xl border border-white/10 bg-white/[0.025]"
            >
              {/* Change header */}
              <div className="border-b border-white/10 p-5">
                <div className="flex flex-wrap items-start justify-between gap-4">
                  <div className="min-w-0">
                    <div className="text-[9px] font-semibold uppercase tracking-[0.16em] text-white/25">
                      File modified
                    </div>

                    <div className="mt-2 break-all font-mono text-sm text-white/75">
                      {change.file || "Unknown file"}
                    </div>
                  </div>

                  <span
                    className={`rounded-full px-3 py-1.5 text-[9px] font-semibold uppercase tracking-wider ${
                      isApplied
                        ? "bg-emerald-400/10 text-emerald-300"
                        : isFailed
                          ? "bg-red-400/10 text-red-300"
                          : "bg-white/5 text-white/40"
                    }`}
                  >
                    {status}
                  </span>
                </div>

                {Array.isArray(record.findings) &&
                  record.findings.length > 0 && (
                    <div className="mt-4 flex flex-wrap gap-2">
                      {record.findings.map((findingId) => (
                        <span
                          key={findingId}
                          className="rounded-full border border-purple-400/15 bg-purple-500/[0.05] px-3 py-1.5 font-mono text-[9px] font-semibold text-purple-300"
                        >
                          {findingId}
                        </span>
                      ))}
                    </div>
                  )}
              </div>

              <div className="space-y-4 p-5">
                {/* Applied state */}
                {isApplied && (
                  <div className="rounded-2xl border border-emerald-400/15 bg-emerald-400/[0.04] p-4">
                    <div className="flex items-start gap-3">
                      <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-emerald-400/10 text-emerald-300">
                        ✓
                      </div>

                      <div>
                        <div className="text-xs font-medium text-emerald-200">
                          Source file modified successfully
                        </div>

                        <div className="mt-1 text-[10px] leading-5 text-white/35">
                          PurpleGuard applied the approved remediation
                          and retained a reversible backup.
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {/* Backup */}
                {record.backup && (
                  <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
                    <div className="text-[9px] font-semibold uppercase tracking-[0.16em] text-white/25">
                      Recovery
                    </div>

                    <div className="mt-2 text-[10px] text-white/35">
                      Backup preserved before modification.
                    </div>

                    <div className="mt-3 break-all rounded-xl border border-white/5 bg-white/[0.02] p-3 font-mono text-[10px] text-white/45">
                      {record.backup}
                    </div>
                  </div>
                )}

                {/* Before / After */}
                {record.original_source &&
                  record.updated_source && (
                    <div className="space-y-3">
                      <div className="text-[9px] font-semibold uppercase tracking-[0.16em] text-white/25">
                        Source transformation
                      </div>

                      <div className="grid gap-3 xl:grid-cols-2">
                        <details
                          open
                          className="overflow-hidden rounded-2xl border border-red-400/10 bg-red-400/[0.025]"
                        >
                          <summary className="cursor-pointer border-b border-white/10 px-4 py-3 text-[10px] font-semibold uppercase tracking-[0.14em] text-red-300">
                            Before — vulnerable source
                          </summary>

                          <pre className="max-h-[420px] overflow-auto p-4 font-mono text-[10px] leading-5 text-white/45">
                            {record.original_source}
                          </pre>
                        </details>

                        <details
                          open
                          className="overflow-hidden rounded-2xl border border-emerald-400/10 bg-emerald-400/[0.025]"
                        >
                          <summary className="cursor-pointer border-b border-white/10 px-4 py-3 text-[10px] font-semibold uppercase tracking-[0.14em] text-emerald-300">
                            After — secured source
                          </summary>

                          <pre className="max-h-[420px] overflow-auto p-4 font-mono text-[10px] leading-5 text-white/55">
                            {record.updated_source}
                          </pre>
                        </details>
                      </div>
                    </div>
                  )}

                {/* Unified diff */}
                {record.patch && (
                  <details className="overflow-hidden rounded-2xl border border-purple-400/10 bg-purple-500/[0.025]">
                    <summary className="cursor-pointer border-b border-white/10 px-4 py-3 text-[10px] font-semibold uppercase tracking-[0.14em] text-purple-300">
                      View complete patch / diff
                    </summary>

                    <pre className="max-h-[500px] overflow-auto p-4 font-mono text-[10px] leading-5 text-white/50">
                      {record.patch}
                    </pre>
                  </details>
                )}

                {/* Patch file */}
                {record.patch_file && (
                  <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
                    <div className="text-[9px] font-semibold uppercase tracking-[0.16em] text-white/25">
                      Generated patch file
                    </div>

                    <div className="mt-2 break-all font-mono text-[10px] text-white/40">
                      {record.patch_file}
                    </div>
                  </div>
                )}

                {/* Verification handoff */}
                <div
                  className={`rounded-2xl border p-4 ${
                    verificationPassed
                      ? "border-emerald-400/15 bg-emerald-400/[0.035]"
                      : "border-amber-400/15 bg-amber-400/[0.035]"
                  }`}
                >
                  <div className="flex items-start gap-3">
                    <div
                      className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-full ${
                        verificationPassed
                          ? "bg-emerald-400/10 text-emerald-300"
                          : "bg-amber-400/10 text-amber-300"
                      }`}
                    >
                      {verificationPassed ? "✓" : "!"}
                    </div>

                    <div>
                      <div
                        className={`text-xs font-medium ${
                          verificationPassed
                            ? "text-emerald-200"
                            : "text-amber-200"
                        }`}
                      >
                        {verificationPassed
                          ? "Security verification passed"
                          : "Verification requires review"}
                      </div>

                      <div className="mt-1 text-[10px] leading-5 text-white/35">
                        {verificationPassed
                          ? "Static analysis, automated tests and adversarial re-validation established that the approved remediation resolved the confirmed attack paths."
                          : "PurpleGuard could not establish a complete security verification across every verification layer."}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Failure message */}
                {isFailed && change.message && (
                  <div className="rounded-2xl border border-red-400/15 bg-red-400/[0.04] p-4">
                    <div className="text-[9px] font-semibold uppercase tracking-[0.16em] text-red-300">
                      Operation failed
                    </div>

                    <p className="mt-2 text-xs leading-5 text-white/45">
                      {change.message}
                    </p>
                  </div>
                )}

                {/* No change */}
                {status === "NO_CHANGE" && (
                  <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
                    <div className="text-[9px] font-semibold uppercase tracking-[0.16em] text-white/25">
                      No source change
                    </div>

                    <p className="mt-2 text-xs leading-5 text-white/40">
                      PurpleGuard generated no source modification for
                      this remediation operation.
                    </p>
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function VerificationPanel({
  result,
}: {
  result: SecureResult | null;
}) {
  if (!result?.verification) {
    return (
      <div className="rounded-3xl border border-white/10 bg-white/[0.025] p-8">
        <div className="text-xs uppercase tracking-[0.18em] text-white/30">
          PurpleGuard Verification
        </div>

        <h2 className="mt-2 text-2xl font-semibold">
          Security verification
        </h2>

        <p className="mt-2 max-w-2xl text-sm leading-6 text-white/40">
          Run an approved PurpleGuard security operation to verify that
          discovered vulnerabilities have actually been remediated.
        </p>
      </div>
    );
  }

  const verification = result.verification;
  const verdict = verification.verdict;

  const staticPassed = verification.static_scan?.passed === true;

  const testsPassed =
    verification.tests?.passed === true ||
    verification.tests?.tests_passed === true;

  const hackerPassed =
    verification.hacker?.status === "SECURITY_VERIFIED" &&
    verification.hacker?.all_attacks_blocked === true;

  const verified =
    verdict?.status === "SECURITY_VERIFIED" &&
    verdict?.all_checks_passed === true;

  const changesApplied =
    result.remediation?.approved === true &&
    (result.remediation?.result?.results?.length || 0) > 0;

  const confirmedAttacks = result.confirmed_attacks || 0;
  const attackPaths = result.recon?.attack_paths || 0;

  const verificationSteps = [
    {
      number: "01",
      title: "Attack discovered",
      description: `${attackPaths} attack path${attackPaths === 1 ? "" : "s"} identified during reconnaissance.`,
      passed: attackPaths > 0,
    },
    {
      number: "02",
      title: "Attack confirmed",
      description: `${confirmedAttacks} vulnerabilit${confirmedAttacks === 1 ? "y" : "ies"} behaviourally validated against the authorised target.`,
      passed: confirmedAttacks > 0,
    },
    {
      number: "03",
      title: "Fix applied",
      description: changesApplied
        ? "Approved remediation changes were applied to the project."
        : "No approved remediation changes were applied.",
      passed: changesApplied,
    },
    {
      number: "04",
      title: "Static rescan",
      description: staticPassed
        ? "Previously detected security issues are no longer present."
        : "Static verification did not pass.",
      passed: staticPassed,
    },
    {
      number: "05",
      title: "Automated tests",
      description: testsPassed
        ? "The project's automated security tests passed."
        : "Automated tests did not pass.",
      passed: testsPassed,
    },
    {
      number: "06",
      title: "Attack re-tested",
      description: hackerPassed
        ? "PurpleGuard re-ran the attack validations against the remediated target."
        : "Adversarial re-validation did not pass.",
      passed: hackerPassed,
    },
    {
      number: "07",
      title: "Attack blocked",
      description: hackerPassed
        ? "Previously confirmed attack paths were blocked."
        : "One or more attack paths remain exploitable.",
      passed: hackerPassed,
    },
  ];

  return (
    <div className="space-y-5">

      <div
        className={`rounded-3xl border p-7 ${
          verified
            ? "border-emerald-400/20 bg-emerald-400/[0.06]"
            : "border-red-400/20 bg-red-400/[0.05]"
        }`}
      >
        <div className="flex flex-col gap-5 md:flex-row md:items-center md:justify-between">
          <div>
            <div className="text-xs uppercase tracking-[0.2em] text-white/35">
              Final security verdict
            </div>

            <div
              className={`mt-2 text-3xl font-semibold ${
                verified ? "text-emerald-300" : "text-red-300"
              }`}
            >
              {verdict?.status || result.status || "UNKNOWN"}
            </div>

            <p className="mt-2 max-w-2xl text-sm leading-6 text-white/45">
              {verified
                ? "PurpleGuard confirmed that the discovered attack paths were remediated and blocked during adversarial re-validation."
                : "PurpleGuard could not establish that every required security verification check passed."}
            </p>
          </div>

          <div
            className={`flex h-20 w-20 shrink-0 items-center justify-center rounded-full border ${
              verified
                ? "border-emerald-400/30 bg-emerald-400/10"
                : "border-red-400/30 bg-red-400/10"
            }`}
          >
            <span
              className={`text-3xl ${
                verified ? "text-emerald-300" : "text-red-300"
              }`}
            >
              {verified ? "✓" : "!"}
            </span>
          </div>
        </div>
      </div>

      <div className="rounded-3xl border border-white/10 bg-white/[0.025] p-6">
        <div className="text-xs uppercase tracking-[0.18em] text-white/30">
          Security proof
        </div>

        <h2 className="mt-2 text-xl font-semibold">
          Attack → Fix → Verify
        </h2>

        <p className="mt-2 text-sm text-white/35">
          PurpleGuard does not treat a static scan as proof. It verifies
          remediation through multiple independent checks.
        </p>

        <div className="mt-6 space-y-3">
          {verificationSteps.map((step, index) => (
            <div
              key={step.number}
              className={`rounded-2xl border p-4 ${
                step.passed
                  ? "border-emerald-400/10 bg-emerald-400/[0.025]"
                  : "border-red-400/10 bg-red-400/[0.025]"
              }`}
            >
              <div className="flex items-start gap-4">
                <div
                  className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-xl text-xs font-semibold ${
                    step.passed
                      ? "bg-emerald-400/10 text-emerald-300"
                      : "bg-red-400/10 text-red-300"
                  }`}
                >
                  {step.passed ? "✓" : step.number}
                </div>

                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-sm font-medium">
                      {step.title}
                    </span>

                    <span
                      className={`text-[10px] uppercase tracking-wider ${
                        step.passed
                          ? "text-emerald-300"
                          : "text-red-300"
                      }`}
                    >
                      {step.passed ? "PASSED" : "FAILED"}
                    </span>
                  </div>

                  <p className="mt-1 text-xs leading-5 text-white/35">
                    {step.description}
                  </p>
                </div>
              </div>

              {index < verificationSteps.length - 1 && (
                <div className="ml-[17px] mt-2 h-2 border-l border-white/10" />
              )}
            </div>
          ))}
        </div>
      </div>

      <div>
        <div className="mb-3 text-xs uppercase tracking-[0.18em] text-white/30">
          Verification checks
        </div>

        <div className="grid gap-4 md:grid-cols-3">
          <VerificationCard
            label="Static rescan"
            passed={staticPassed}
          />

          <VerificationCard
            label="Automated tests"
            passed={testsPassed}
          />

          <VerificationCard
            label="Hacker re-validation"
            passed={hackerPassed}
          />
        </div>
      </div>

      {verification.hacker?.results &&
        verification.hacker.results.length > 0 && (
          <div className="rounded-3xl border border-white/10 bg-white/[0.025] p-6">
            <div className="flex flex-col gap-2 md:flex-row md:items-end md:justify-between">
              <div>
                <div className="text-xs uppercase tracking-[0.18em] text-white/30">
                  Adversarial verification
                </div>

                <h2 className="mt-2 text-lg font-semibold">
                  Re-attack results
                </h2>

                <p className="mt-1 text-sm text-white/35">
                  Previously confirmed attack paths were tested again after
                  remediation.
                </p>
              </div>

              <div
                className={`text-xs font-medium ${
                  hackerPassed
                    ? "text-emerald-300"
                    : "text-red-300"
                }`}
              >
                {hackerPassed
                  ? "ALL ATTACKS BLOCKED"
                  : "ATTACKS NOT FULLY BLOCKED"}
              </div>
            </div>

            <div className="mt-5 space-y-3">
              {verification.hacker.results.map((item, index) => {
                const blocked = item.blocked === true;

                return (
                  <div
                    key={item.path_id || item.finding_id || index}
                    className="rounded-2xl border border-white/10 p-4"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-sm font-medium">
                          {item.category || "Security attack"}
                        </span>

                        {item.severity && (
                          <span
                            className={`rounded-full px-2 py-1 text-[10px] ${severityClass(
                              item.severity
                            )}`}
                          >
                            {item.severity}
                          </span>
                        )}
                      </div>

                      <span
                        className={`text-xs font-medium ${
                          blocked
                            ? "text-emerald-300"
                            : "text-red-300"
                        }`}
                      >
                        {blocked
                          ? "✓ ATTACK BLOCKED"
                          : "✕ ATTACK STILL WORKS"}
                      </span>
                    </div>

                    {item.payload && (
                      <div className="mt-3">
                        <div className="text-[10px] uppercase tracking-wider text-white/25">
                          Payload
                        </div>

                        <code className="mt-1 block overflow-x-auto rounded-xl bg-black/20 p-3 font-mono text-xs text-white/50">
                          {item.payload}
                        </code>
                      </div>
                    )}

                    {item.evidence && (
                      <div className="mt-3 text-xs leading-5 text-white/40">
                        {item.evidence}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}

      <div className="rounded-3xl border border-white/10 bg-white/[0.025] p-6">
        <div className="text-xs uppercase tracking-[0.18em] text-white/30">
          Verification state
        </div>

        <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <div className="rounded-2xl border border-white/10 p-4">
            <div className="text-xs text-white/30">
              Static analysis
            </div>

            <div className="mt-2 text-sm font-medium">
              {verdict?.static_scan_passed ? "PASSED" : "FAILED"}
            </div>
          </div>

          <div className="rounded-2xl border border-white/10 p-4">
            <div className="text-xs text-white/30">
              Tests
            </div>

            <div className="mt-2 text-sm font-medium">
              {verdict?.tests_passed ? "PASSED" : "FAILED"}
            </div>
          </div>

          <div className="rounded-2xl border border-white/10 p-4">
            <div className="text-xs text-white/30">
              Hacker verification
            </div>

            <div className="mt-2 text-sm font-medium">
              {verdict?.hacker_verification_passed
                ? "PASSED"
                : "FAILED"}
            </div>
          </div>

          <div className="rounded-2xl border border-white/10 p-4">
            <div className="text-xs text-white/30">
              All checks
            </div>

            <div
              className={`mt-2 text-sm font-semibold ${
                verdict?.all_checks_passed
                  ? "text-emerald-300"
                  : "text-red-300"
              }`}
            >
              {verdict?.all_checks_passed
                ? "PASSED"
                : "FAILED"}
            </div>
          </div>
        </div>
      </div>

    </div>
  );
}

function VerificationCard({
  label,
  passed,
}: {
  label: string;
  passed: boolean | undefined;
}) {
  return (
    <div className="rounded-3xl border border-white/10 bg-white/[0.025] p-5">
      <div className="text-xs uppercase tracking-wider text-white/30">
        {label}
      </div>

      <div
        className={`mt-3 text-xl font-semibold ${
          passed ? "text-emerald-300" : "text-red-300"
        }`}
      >
        {passed === undefined
          ? "NOT RUN"
          : boolLabel(passed)}
      </div>
    </div>
  );
}

// ─── Workforce (real Hacker backend) ─────────────────────────

type WorkforceCapability = {
  agent_id: string;
  operation: string;
  engine: string;
  executable: boolean;
  state: string;
  unavailable_reason: string;
};

type WorkforceEvidence = {
  what_tested?: string;
  where_tested?: string;
  what_happened?: string;
};

type WorkforceSource = {
  agent_id?: string;
  task_id?: string;
  correlation_id?: string;
};

type CanonicalFinding = {
  fingerprint: string;
  rule_id?: string;
  name?: string;
  severity?: string;
  file?: string;
  line?: number;
  code?: string;
  validation_state?: string;
  remediation_state?: string;
  verification_state?: string;
  sources?: WorkforceSource[];
  evidence?: WorkforceEvidence[];
};

type ParticipatingAgent = {
  agent_id: string;
  role: string;
  status: string;
  engine: string;
  finding_count: number;
  evidence_count: number;
  confidence: number;
};

type Assessment = {
  target?: string;
  participating_agents: ParticipatingAgent[];
  canonical_findings: CanonicalFinding[];
  corroboration: {
    agent_count: number;
    distinct_engines: string[];
    corroborated_count: number;
    single_agent_count: number;
    independent_corroboration: boolean;
  };
};

type HandoffItem = {
  fingerprint: string;
  rule_id?: string;
  severity?: string;
  file?: string;
  line?: number;
  validation_state?: string;
  sources?: WorkforceSource[];
  evidence?: WorkforceEvidence[];
  stage?: string;
  verification?: { verified?: boolean; status?: string } | null;
};

function workforceStateClass(state: string) {
  if (state === "VERIFIED") return "bg-emerald-400/10 text-emerald-300";
  if (state === "CORROBORATED") return "bg-emerald-400/10 text-emerald-300";
  if (state === "READY_FOR_DEVELOPER") return "bg-purple-400/10 text-purple-300";
  if (state === "REQUIRES_VALIDATION") return "bg-amber-400/10 text-amber-300";
  if (state === "REMEDIATION_PENDING") return "bg-orange-400/10 text-orange-300";
  if (state === "RETESTING") return "bg-cyan-400/10 text-cyan-300";
  if (state === "VALIDATING") return "bg-indigo-400/10 text-indigo-300";
  if (state === "DISCOVERED") return "bg-sky-400/10 text-sky-300";
  if (state === "FAILED") return "bg-red-400/10 text-red-300";
  return "bg-white/5 text-white/40";
}

function canonicalState(
  finding: CanonicalFinding,
  pendingByFingerprint: Record<string, HandoffItem>
): string {
  const item = pendingByFingerprint[finding.fingerprint];

  if (item) {
    if (item.stage === "verified") return "VERIFIED";
    if (item.stage === "awaiting_approval") return "READY_FOR_DEVELOPER";
    if (item.stage === "remediated_not_verified") return "RETESTING";
    if (item.stage === "remediation_unavailable") return "REMEDIATION_PENDING";
    if (item.stage === "not_verified") return "FAILED";
    return "REMEDIATION_PENDING";
  }

  if (finding.validation_state === "corroborated") return "CORROBORATED";
  return "REQUIRES_VALIDATION";
}

function WorkforcePanel({
  target,
  apiUrl,
}: {
  target: string;
  apiUrl: string;
}) {
  const [capabilities, setCapabilities] = useState<WorkforceCapability[]>([]);
  const [findings, setFindings] = useState<CanonicalFinding[]>([]);
  const [pending, setPending] = useState<HandoffItem[]>([]);
  const [assessment, setAssessment] = useState<Assessment | null>(null);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  async function refresh() {
    try {
      const [caps, found, handoff] = await Promise.all([
        fetch(`${apiUrl}/workforce/capabilities`),
        fetch(`${apiUrl}/workforce/findings`),
        fetch(`${apiUrl}/workforce/handoff`),
      ]);

      const capsJson = await caps.json();
      const foundJson = await found.json();
      const handoffJson = await handoff.json();

      setCapabilities(capsJson.capabilities || []);
      setFindings(foundJson.findings || []);
      setPending(handoffJson.pending || []);
    } catch {
      setError(
        "Could not reach the PurpleGuard backend. Is the API running?"
      );
    }
  }

  useEffect(() => {
    // Loads from the backend after the effect returns; the state
    // updates happen inside the awaited fetch, not synchronously.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function runAssessment() {
    if (!target.trim() || busy) return;

    setBusy("assess");
    setError("");
    setNotice("");

    try {
      const response = await fetch(`${apiUrl}/workforce/assess`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target }),
      });

      const data = await response.json();

      if (!response.ok) {
        setError(data.error || "Assessment failed.");
        return;
      }

      setAssessment(data.assessment || null);
      setNotice(
        "Assessment complete. Findings were produced by the real engines and correlated."
      );
      await refresh();
    } catch {
      setError("Assessment request failed.");
    } finally {
      setBusy("");
    }
  }

  async function sendToDeveloper() {
    if (!target.trim() || busy) return;

    setBusy("handoff");
    setError("");
    setNotice("");

    try {
      const response = await fetch(`${apiUrl}/workforce/handoff`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target }),
      });

      const data = await response.json();

      if (!response.ok) {
        setError(data.error || "Handoff failed.");
        return;
      }

      setNotice(
        `Sent ${data.delivered ?? 0} canonical finding(s) to the developer. Approval is required before any source change.`
      );
      await refresh();
    } catch {
      setError("Handoff request failed.");
    } finally {
      setBusy("");
    }
  }

  async function approve(fingerprint: string) {
    if (busy) return;

    setBusy(`approve:${fingerprint}`);
    setError("");
    setNotice("");

    try {
      const response = await fetch(`${apiUrl}/workforce/approve`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ fingerprint, approve: true, target }),
      });

      const data = await response.json();

      if (!response.ok) {
        setError(data.error || "Approval failed.");
        return;
      }

      const verdict = data.verification?.verified
        ? "remediation applied and VERIFIED by a genuine re-test"
        : "remediation did not pass the re-test";

      setNotice(`Result: ${data.status} — ${verdict}.`);
      await refresh();
    } catch {
      setError("Approval request failed.");
    } finally {
      setBusy("");
    }
  }

  const pendingByFingerprint: Record<string, HandoffItem> = {};
  for (const item of pending) {
    pendingByFingerprint[item.fingerprint] = item;
  }

  const allCanonical: CanonicalFinding[] = assessment
    ? assessment.canonical_findings
    : findings;

  const executable = capabilities.filter((c) => c.executable).length;
  const unavailable = capabilities.length - executable;

  const running = busy === "assess";

  const pipeline = [
    { label: "DISCOVERED", active: running || allCanonical.length > 0 },
    { label: "VALIDATING", active: running || Boolean(assessment) },
    {
      label: "CORROBORATED",
      active: Boolean(
        assessment && assessment.corroboration.independent_corroboration
      ),
    },
    { label: "READY_FOR_DEVELOPER", active: pending.length > 0 },
    {
      label: "VERIFIED",
      active: pending.some((item) => item.stage === "verified"),
    },
  ];

  return (
    <div className="space-y-6">
      <div className="rounded-3xl border border-purple-500/20 bg-purple-500/5 p-6">
        <div className="text-xs font-semibold uppercase tracking-[0.18em] text-purple-300">
          Security Agent Workforce
        </div>

        <h2 className="mt-2 text-2xl font-semibold">
          Real agents. Real engines. Real evidence.
        </h2>

        <p className="mt-2 max-w-2xl text-sm leading-6 text-white/40">
          A discovery agent and an independent validation agent run the
          real PurpleGuard engines against your authorized target. A
          finding is only corroborated when two distinct agents produced
          evidence for it. Every value below comes from the persisted
          canonical finding — nothing is simulated.
        </p>

        <div className="mt-5 flex flex-wrap items-center gap-3">
          <button
            onClick={runAssessment}
            disabled={running || Boolean(busy)}
            className="rounded-xl bg-purple-500/90 px-4 py-2 text-sm font-semibold text-white transition hover:bg-purple-400 disabled:opacity-40"
          >
            {running ? "Running agents…" : "Run workforce assessment"}
          </button>

          <button
            onClick={sendToDeveloper}
            disabled={Boolean(busy) || pending.length === 0}
            className="rounded-xl border border-white/15 px-4 py-2 text-sm font-semibold text-white/80 transition hover:bg-white/5 disabled:opacity-40"
          >
            {busy === "handoff" ? "Sending…" : "Send to developer"}
          </button>

          <button
            onClick={refresh}
            disabled={Boolean(busy)}
            className="rounded-xl border border-white/10 px-4 py-2 text-sm text-white/60 transition hover:bg-white/5 disabled:opacity-40"
          >
            Refresh
          </button>

          <span className="text-xs text-white/35">
            target: <span className="text-white/60">{target || "—"}</span>
          </span>
        </div>

        <div className="mt-5 flex flex-wrap gap-2">
          {pipeline.map((stage) => (
            <span
              key={stage.label}
              className={`rounded-full px-3 py-1 text-[11px] font-semibold tracking-wide ${
                stage.active
                  ? workforceStateClass(stage.label)
                  : "bg-white/5 text-white/25"
              }`}
            >
              {stage.label}
            </span>
          ))}
        </div>

        {error && (
          <div className="mt-4 rounded-xl border border-red-400/20 bg-red-400/5 p-3 text-sm text-red-300">
            {error}
          </div>
        )}

        {notice && (
          <div className="mt-4 rounded-xl border border-emerald-400/20 bg-emerald-400/5 p-3 text-sm text-emerald-200">
            {notice}
          </div>
        )}

        <div className="mt-5 grid grid-cols-2 gap-3 sm:grid-cols-4">
          <div className="rounded-2xl border border-white/10 p-4">
            <div className="text-xs uppercase tracking-wider text-white/30">
              Executable
            </div>
            <div className="mt-2 text-2xl font-semibold text-emerald-300">
              {executable}
            </div>
          </div>

          <div className="rounded-2xl border border-white/10 p-4">
            <div className="text-xs uppercase tracking-wider text-white/30">
              Unavailable
            </div>
            <div className="mt-2 text-2xl font-semibold text-white/50">
              {unavailable}
            </div>
          </div>

          <div className="rounded-2xl border border-white/10 p-4">
            <div className="text-xs uppercase tracking-wider text-white/30">
              Canonical findings
            </div>
            <div className="mt-2 text-2xl font-semibold">
              {allCanonical.length}
            </div>
          </div>

          <div className="rounded-2xl border border-white/10 p-4">
            <div className="text-xs uppercase tracking-wider text-white/30">
              Pending developer
            </div>
            <div className="mt-2 text-2xl font-semibold text-purple-300">
              {pending.length}
            </div>
          </div>
        </div>
      </div>

      {assessment && (
        <div className="rounded-3xl border border-white/10 bg-white/[0.025] p-6">
          <h3 className="text-lg font-semibold">Agent execution</h3>

          <div className="mt-4 grid gap-3 md:grid-cols-2">
            {assessment.participating_agents.map((agent) => (
              <div
                key={agent.agent_id}
                className="rounded-2xl border border-white/10 p-4"
              >
                <div className="flex items-center justify-between">
                  <div className="text-sm font-semibold">
                    {agent.agent_id}
                  </div>
                  <span className="rounded-full bg-white/5 px-2 py-0.5 text-[10px] uppercase tracking-wider text-white/50">
                    {agent.status}
                  </span>
                </div>

                <div className="mt-2 text-xs text-white/40">
                  role: {agent.role}
                </div>

                <div className="mt-1 break-all text-[11px] text-white/30">
                  engine: {agent.engine}
                </div>

                <div className="mt-3 flex gap-4 text-xs text-white/50">
                  <span>findings: {agent.finding_count}</span>
                  <span>evidence: {agent.evidence_count}</span>
                  <span>confidence: {agent.confidence}</span>
                </div>
              </div>
            ))}
          </div>

          <div className="mt-4 rounded-2xl border border-white/10 p-4 text-sm">
            <div className="text-xs uppercase tracking-wider text-white/30">
              Independent corroboration
            </div>

            <div className="mt-2 flex flex-wrap gap-x-6 gap-y-1 text-white/60">
              <span>agents: {assessment.corroboration.agent_count}</span>
              <span>
                corroborated: {assessment.corroboration.corroborated_count}
              </span>
              <span>single-agent: {assessment.corroboration.single_agent_count}</span>
              <span>
                independent:{" "}
                {assessment.corroboration.independent_corroboration
                  ? "YES"
                  : "NO"}
              </span>
            </div>

            <div className="mt-2 break-all text-[11px] text-white/30">
              distinct engines:{" "}
              {assessment.corroboration.distinct_engines.join(", ")}
            </div>
          </div>
        </div>
      )}

      <div className="rounded-3xl border border-white/10 bg-white/[0.025] p-6">
        <h3 className="text-lg font-semibold">Canonical findings</h3>

        <p className="mt-1 text-sm text-white/35">
          Deduplicated findings with the evidence and provenance of every
          agent that produced them.
        </p>

        {allCanonical.length === 0 ? (
          <div className="mt-5 rounded-2xl border border-white/10 bg-black/20 p-5 text-sm text-white/40">
            No canonical findings yet. Run a workforce assessment against an
            authorized target.
          </div>
        ) : (
          <div className="mt-5 space-y-4">
            {allCanonical.map((finding) => {
              const state = canonicalState(finding, pendingByFingerprint);
              const item = pendingByFingerprint[finding.fingerprint];

              return (
                <div
                  key={finding.fingerprint}
                  className="rounded-2xl border border-white/10 p-4"
                >
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div className="flex items-center gap-3">
                      <span
                        className={`rounded-md px-2 py-0.5 text-[11px] font-semibold ${severityClass(
                          finding.severity || "LOW"
                        )}`}
                      >
                        {finding.severity}
                      </span>

                      <span className="text-sm font-semibold">
                        [{finding.rule_id}] {finding.name || "Finding"}
                      </span>
                    </div>

                    <span
                      className={`rounded-full px-3 py-1 text-[11px] font-semibold ${workforceStateClass(
                        state
                      )}`}
                    >
                      {state}
                    </span>
                  </div>

                  <div className="mt-2 text-xs text-white/45">
                    {displayFile(finding.file || "")}:{finding.line}{" "}
                    {finding.code ? `— ${finding.code}` : ""}
                  </div>

                  <div className="mt-3 text-[11px] uppercase tracking-wider text-white/30">
                    reported by
                  </div>

                  <div className="mt-1 flex flex-wrap gap-2">
                    {(finding.sources || []).map((source, index) => (
                      <span
                        key={`${source.agent_id}-${index}`}
                        className="rounded-md bg-white/5 px-2 py-0.5 text-[11px] text-white/60"
                      >
                        {source.agent_id}
                      </span>
                    ))}
                  </div>

                  <div className="mt-3 text-[11px] uppercase tracking-wider text-white/30">
                    evidence ({finding.evidence?.length ?? 0})
                  </div>

                  <div className="mt-2 space-y-2">
                    {(finding.evidence || []).map((ev, index) => (
                      <div
                        key={index}
                        className="rounded-xl border border-white/10 bg-black/20 p-3 text-xs text-white/50"
                      >
                        <div className="text-white/70">
                          {ev.where_tested || "—"}
                        </div>
                        <div className="mt-1">{ev.what_tested}</div>
                        <div className="mt-1 text-white/40">
                          {ev.what_happened}
                        </div>
                      </div>
                    ))}
                  </div>

                  {item && item.stage === "awaiting_approval" && (
                    <div className="mt-4 flex items-center justify-between rounded-xl border border-purple-500/20 bg-purple-500/5 p-3">
                      <div className="text-xs text-purple-200">
                        Ready for the developer. Approval required before any
                        source change.
                      </div>

                      <button
                        onClick={() => approve(finding.fingerprint)}
                        disabled={Boolean(busy)}
                        className="rounded-lg bg-purple-500/90 px-3 py-1.5 text-xs font-semibold text-white transition hover:bg-purple-400 disabled:opacity-40"
                      >
                        {busy === `approve:${finding.fingerprint}`
                          ? "Remediating…"
                          : "Approve & remediate"}
                      </button>
                    </div>
                  )}

                  {item?.verification && (
                    <div className="mt-3 rounded-xl border border-white/10 bg-black/20 p-3 text-xs text-white/50">
                      re-test: {item.verification.verified ? "VERIFIED" : item.verification.status}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      <div className="rounded-3xl border border-white/10 bg-white/[0.025] p-6">
        <h3 className="text-lg font-semibold">Capability states</h3>

        <p className="mt-1 text-sm text-white/35">
          What actually executes — and what is honestly unavailable.
        </p>

        <div className="mt-5 grid gap-2 md:grid-cols-2">
          {capabilities.map((cap) => (
            <div
              key={cap.agent_id}
              className="flex items-start justify-between gap-3 rounded-xl border border-white/10 p-3"
            >
              <div className="min-w-0">
                <div className="text-sm font-semibold">{cap.agent_id}</div>

                <div className="mt-1 break-all text-[11px] text-white/30">
                  {cap.executable ? cap.engine : cap.unavailable_reason}
                </div>
              </div>

              <span
                className={`shrink-0 rounded-full px-2 py-0.5 text-[10px] font-semibold ${workforceStateClass(
                  cap.state
                )}`}
              >
                {cap.state}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── Landing (product experience) ─────────────────────────

function LandingScreen({ onEnter }: { onEnter: () => void }) {
  const features = [
    {
      icon: "▤",
      title: "Real static scanner",
      body: "PG001–PG012 run against your authorized source. Findings are read from the engine, never mocked.",
    },
    {
      icon: "◈",
      title: "Red-team Hacker engine",
      body: "The Python security analyzer builds attack paths and independently corroborates them against a second engine.",
    },
    {
      icon: "⬡",
      title: "Security workforce",
      body: "Multi-agent execution with correlation, provenance and canonical findings that persist across runs.",
    },
    {
      icon: "⌘",
      title: "Approval-gated remediation",
      body: "Nothing touches your source until a human approves. Then a provably safe patch is applied.",
    },
    {
      icon: "✓",
      title: "Genuine re-test",
      body: "Verification comes from a fresh scan showing the rule no longer fires — not from the fact a patch was written.",
    },
    {
      icon: "◷",
      title: "Honest availability",
      body: "13 engines execute. Capabilities without a real primitive are reported UNAVAILABLE with the exact reason.",
    },
  ];

  const pipeline = [
    "Discover",
    "Validate",
    "Corroborate",
    "Publish",
    "Handoff",
    "Approve",
    "Remediate",
    "Re-test",
    "Verify",
  ];

  return (
    <main className="min-h-screen bg-[#08070c] text-white">
      <div className="pointer-events-none fixed inset-0 overflow-hidden">
        <div className="absolute -top-40 left-1/2 h-[36rem] w-[36rem] -translate-x-1/2 rounded-full bg-purple-600/20 blur-[140px]" />
        <div className="absolute bottom-0 right-0 h-[28rem] w-[28rem] rounded-full bg-indigo-600/10 blur-[120px]" />
      </div>

      <header className="relative mx-auto flex max-w-7xl items-center justify-between px-4 py-6 md:px-8">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-purple-500 font-black">
            P
          </div>

          <div>
            <div className="font-semibold tracking-tight">PurpleGuard</div>
            <div className="text-[10px] uppercase tracking-[0.2em] text-white/40">
              AI Security Engineer
            </div>
          </div>
        </div>

        <button
          onClick={onEnter}
          className="rounded-xl border border-white/15 px-4 py-2 text-sm font-semibold text-white/80 transition hover:bg-white/5"
        >
          Enter console
        </button>
      </header>

      <section className="relative mx-auto max-w-7xl px-4 pb-24 pt-8 md:px-8 md:pt-16">
        <div className="inline-flex items-center gap-2 rounded-full border border-purple-500/25 bg-purple-500/10 px-3 py-1.5 text-xs text-purple-200">
          <span className="h-1.5 w-1.5 rounded-full bg-purple-400" />
          Real engines · real evidence · honest availability
        </div>

        <h1 className="mt-6 max-w-4xl text-4xl font-semibold leading-[1.05] tracking-tight md:text-6xl">
          Offensive security that proves the risk — and then proves the fix.
        </h1>

        <p className="mt-6 max-w-2xl text-base leading-7 text-white/50">
          PurpleGuard pairs a real static scanner with a red-team Hacker
          engine, multi-agent corroboration, approval-gated remediation, and a
          genuine re-test. Every finding you see comes from a real engine run.
        </p>

        <div className="mt-8 flex flex-wrap gap-3">
          <button
            onClick={onEnter}
            className="rounded-xl bg-purple-500 px-6 py-3 text-sm font-semibold shadow-lg shadow-purple-950/40 transition hover:bg-purple-400"
          >
            Launch the console
          </button>

          <button
            onClick={onEnter}
            className="rounded-xl border border-white/15 px-6 py-3 text-sm font-semibold text-white/80 transition hover:bg-white/5"
          >
            Explore the Hacker engine
          </button>
        </div>

        <div className="mt-16 grid gap-4 sm:grid-cols-3">
          <div className="rounded-3xl border border-white/10 bg-white/[0.025] p-6">
            <div className="text-3xl font-semibold text-emerald-300">13</div>
            <div className="mt-1 text-xs uppercase tracking-wider text-white/35">
              Executable engines
            </div>
          </div>

          <div className="rounded-3xl border border-white/10 bg-white/[0.025] p-6">
            <div className="text-3xl font-semibold text-white/60">7</div>
            <div className="mt-1 text-xs uppercase tracking-wider text-white/35">
              Honestly unavailable
            </div>
          </div>

          <div className="rounded-3xl border border-white/10 bg-white/[0.025] p-6">
            <div className="text-3xl font-semibold text-purple-300">1</div>
            <div className="mt-1 text-xs uppercase tracking-wider text-white/35">
              Unified real backend
            </div>
          </div>
        </div>

        <div className="mt-16 grid gap-4 md:grid-cols-3">
          {features.map((feature) => (
            <div
              key={feature.title}
              className="rounded-3xl border border-white/10 bg-white/[0.025] p-6 transition hover:border-purple-500/25 hover:bg-white/[0.04]"
            >
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-purple-500/15 text-lg text-purple-200">
                {feature.icon}
              </div>

              <div className="mt-4 text-base font-semibold">
                {feature.title}
              </div>

              <p className="mt-2 text-sm leading-6 text-white/45">
                {feature.body}
              </p>
            </div>
          ))}
        </div>

        <div className="mt-16 rounded-3xl border border-white/10 bg-white/[0.025] p-6 md:p-8">
          <div className="text-xs font-semibold uppercase tracking-[0.18em] text-purple-300">
            How it works
          </div>

          <div className="mt-5 flex flex-wrap items-center gap-2">
            {pipeline.map((step, index) => (
              <div key={step} className="flex items-center gap-2">
                <span className="rounded-full border border-white/10 bg-black/20 px-3 py-1.5 text-xs text-white/70">
                  {step}
                </span>

                {index < pipeline.length - 1 && (
                  <span className="text-white/20">→</span>
                )}
              </div>
            ))}
          </div>
        </div>

        <footer className="mt-16 border-t border-white/10 pt-6 text-xs text-white/35">
          Authorized local targets only. PurpleGuard sends harmless controlled
          payloads and never performs destructive actions or external network
          access.
        </footer>
      </section>
    </main>
  );
}

// ─── Developer (real handoff → approval → remediation → re-test) ───

function DeveloperPanel({
  target,
  apiUrl,
}: {
  target: string;
  apiUrl: string;
}) {
  const [pending, setPending] = useState<HandoffItem[]>([]);
  const [findings, setFindings] = useState<CanonicalFinding[]>([]);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  async function refresh() {
    try {
      const [handoff, found] = await Promise.all([
        fetch(`${apiUrl}/workforce/handoff`),
        fetch(`${apiUrl}/workforce/findings`),
      ]);

      const handoffJson = await handoff.json();
      const foundJson = await found.json();

      setPending(handoffJson.pending || []);
      setFindings(foundJson.findings || []);
    } catch {
      setError(
        "Could not reach the PurpleGuard backend. Is the API running?"
      );
    }
  }

  useEffect(() => {
    // Loads from the backend after the effect returns; the state
    // updates happen inside the awaited fetch, not synchronously.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function send() {
    if (busy || !target.trim()) return;

    setBusy("send");
    setError("");
    setNotice("");

    try {
      const response = await fetch(`${apiUrl}/workforce/handoff`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target }),
      });

      const data = await response.json();

      if (!response.ok) {
        setError(data.error || "Handoff failed.");
        return;
      }

      setNotice(
        `Delivered ${data.delivered ?? 0} finding(s) to the developer inbox. Approval is required before any source change.`
      );
      await refresh();
    } catch {
      setError("Handoff request failed.");
    } finally {
      setBusy("");
    }
  }

  async function approve(fingerprint: string) {
    if (busy) return;

    setBusy(`approve:${fingerprint}`);
    setError("");
    setNotice("");

    try {
      const response = await fetch(`${apiUrl}/workforce/approve`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ fingerprint, approve: true, target }),
      });

      const data = await response.json();

      if (!response.ok) {
        setError(data.error || "Approval failed.");
        return;
      }

      const verdict = data.verification?.verified
        ? "remediation applied and VERIFIED by a genuine re-test"
        : "remediation did not pass the re-test";

      setNotice(`Result: ${data.status} — ${verdict}.`);
      await refresh();
    } catch {
      setError("Approval request failed.");
    } finally {
      setBusy("");
    }
  }

  const stages = [
    "Finding",
    "Evidence",
    "Approval",
    "Remediation",
    "Re-test",
    "Verification",
  ];

  return (
    <div className="space-y-6">
      <div className="rounded-3xl border border-purple-500/20 bg-purple-500/5 p-6">
        <div className="text-xs font-semibold uppercase tracking-[0.18em] text-purple-300">
          Developer workflow
        </div>

        <h2 className="mt-2 text-2xl font-semibold">
          Finding → approval → remediation → re-test → verification
        </h2>

        <p className="mt-2 max-w-2xl text-sm leading-6 text-white/40">
          The developer inbox holds the real canonical findings produced by the
          security workforce. Nothing is written to source until an explicit
          approval, and a finding is only verified when a genuine re-test shows
          the original rule no longer fires.
        </p>

        <div className="mt-5 flex flex-wrap gap-2">
          {stages.map((stage) => (
            <span
              key={stage}
              className="rounded-full bg-white/5 px-3 py-1 text-[11px] font-semibold tracking-wide text-white/50"
            >
              {stage}
            </span>
          ))}
        </div>

        <div className="mt-5 flex flex-wrap items-center gap-3">
          <button
            onClick={send}
            disabled={Boolean(busy) || !target.trim()}
            className="rounded-xl bg-purple-500/90 px-4 py-2 text-sm font-semibold text-white transition hover:bg-purple-400 disabled:opacity-40"
          >
            {busy === "send" ? "Sending…" : "Send findings to developer"}
          </button>

          <button
            onClick={refresh}
            disabled={Boolean(busy)}
            className="rounded-xl border border-white/10 px-4 py-2 text-sm text-white/60 transition hover:bg-white/5 disabled:opacity-40"
          >
            Refresh
          </button>

          <span className="text-xs text-white/35">
            target: <span className="text-white/60">{target || "—"}</span>
          </span>
        </div>

        {error && (
          <div className="mt-4 rounded-xl border border-red-400/20 bg-red-400/5 p-3 text-sm text-red-300">
            {error}
          </div>
        )}

        {notice && (
          <div className="mt-4 rounded-xl border border-emerald-400/20 bg-emerald-400/5 p-3 text-sm text-emerald-200">
            {notice}
          </div>
        )}
      </div>

      <div className="rounded-3xl border border-white/10 bg-white/[0.025] p-6">
        <h3 className="text-lg font-semibold">Developer inbox</h3>

        <p className="mt-1 text-sm text-white/35">
          {pending.length} finding(s) awaiting approval. Evidence is attached
          from the canonical finding.
        </p>

        {pending.length === 0 ? (
          <div className="mt-5 rounded-2xl border border-white/10 bg-black/20 p-5 text-sm text-white/40">
            The inbox is empty. Send findings from the Hacker panel or use the
            button above.
          </div>
        ) : (
          <div className="mt-5 space-y-4">
            {pending.map((item) => (
              <div
                key={item.fingerprint}
                className="rounded-2xl border border-white/10 p-4"
              >
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div className="flex items-center gap-3">
                    <span
                      className={`rounded-md px-2 py-0.5 text-[11px] font-semibold ${severityClass(
                        item.severity || "LOW"
                      )}`}
                    >
                      {item.severity}
                    </span>

                    <span className="text-sm font-semibold">
                      [{item.rule_id}] {displayFile(item.file || "")}:
                      {item.line}
                    </span>
                  </div>

                  <span className="rounded-full bg-purple-400/10 px-3 py-1 text-[11px] font-semibold text-purple-300">
                    AWAITING_APPROVAL
                  </span>
                </div>

                <div className="mt-3 text-[11px] uppercase tracking-wider text-white/30">
                  evidence ({(item.evidence || []).length})
                </div>

                <div className="mt-2 space-y-2">
                  {(item.evidence || []).map((ev, index) => (
                    <div
                      key={index}
                      className="rounded-xl border border-white/10 bg-black/20 p-3 text-xs text-white/50"
                    >
                      <div className="text-white/70">
                        {ev.where_tested || "—"}
                      </div>
                      <div className="mt-1">{ev.what_tested}</div>
                      <div className="mt-1 text-white/40">
                        {ev.what_happened}
                      </div>
                    </div>
                  ))}
                </div>

                <div className="mt-4 flex items-center justify-between gap-3 rounded-xl border border-purple-500/20 bg-purple-500/5 p-3">
                  <div className="text-xs text-purple-200">
                    Approval required before any source change.
                  </div>

                  <button
                    onClick={() => approve(item.fingerprint)}
                    disabled={Boolean(busy)}
                    className="shrink-0 rounded-lg bg-purple-500/90 px-3 py-1.5 text-xs font-semibold text-white transition hover:bg-purple-400 disabled:opacity-40"
                  >
                    {busy === `approve:${item.fingerprint}`
                      ? "Remediating…"
                      : "Approve & remediate"}
                  </button>
                </div>

                {item.verification && (
                  <div className="mt-3 rounded-xl border border-white/10 bg-black/20 p-3 text-xs text-white/50">
                    re-test:{" "}
                    {item.verification.verified
                      ? "VERIFIED"
                      : item.verification.status}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="rounded-3xl border border-white/10 bg-white/[0.025] p-6">
        <h3 className="text-lg font-semibold">Canonical findings</h3>

        <p className="mt-1 text-sm text-white/35">
          {findings.length} persisted finding(s) available for handoff.
        </p>

        <div className="mt-4 space-y-2">
          {findings.map((finding) => (
            <div
              key={finding.fingerprint}
              className="flex items-center justify-between gap-3 rounded-xl border border-white/10 p-3"
            >
              <div className="min-w-0">
                <div className="text-sm font-semibold">
                  [{finding.rule_id}] {finding.name}
                </div>

                <div className="mt-1 truncate text-[11px] text-white/35">
                  {displayFile(finding.file || "")}:{finding.line}
                </div>
              </div>

              <span
                className={`shrink-0 rounded-full px-2 py-0.5 text-[10px] font-semibold ${workforceStateClass(
                  finding.validation_state === "corroborated"
                    ? "CORROBORATED"
                    : "REQUIRES_VALIDATION"
                )}`}
              >
                {(finding.validation_state || "unvalidated").toUpperCase()}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── History (persisted findings from the real backend) ──────

function HistoryPanel({
  apiUrl,
  result,
}: {
  apiUrl: string;
  result: SecureResult | null;
}) {
  const [findings, setFindings] = useState<CanonicalFinding[]>([]);
  const [pending, setPending] = useState<HandoffItem[]>([]);
  const [error, setError] = useState("");

  async function refresh() {
    try {
      const [found, handoff] = await Promise.all([
        fetch(`${apiUrl}/workforce/findings`),
        fetch(`${apiUrl}/workforce/handoff`),
      ]);

      const foundJson = await found.json();
      const handoffJson = await handoff.json();

      setFindings(foundJson.findings || []);
      setPending(handoffJson.pending || []);
    } catch {
      setError(
        "Could not reach the PurpleGuard backend. Is the API running?"
      );
    }
  }

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="space-y-6">
      <div className="rounded-3xl border border-purple-500/20 bg-purple-500/5 p-6">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <div className="text-xs font-semibold uppercase tracking-[0.18em] text-purple-300">
              Persisted history
            </div>

            <h2 className="mt-2 text-2xl font-semibold">
              Security findings that survive a restart
            </h2>

            <p className="mt-2 max-w-2xl text-sm leading-6 text-white/40">
              Canonical findings and the developer queue are read from the
              PurpleGuard store, so the record persists across runs.
            </p>
          </div>

          <button
            onClick={refresh}
            className="rounded-xl border border-white/10 px-4 py-2 text-sm text-white/60 transition hover:bg-white/5"
          >
            Refresh
          </button>
        </div>

        <div className="mt-5 grid grid-cols-2 gap-3 sm:grid-cols-3">
          <div className="rounded-2xl border border-white/10 p-4">
            <div className="text-xs uppercase tracking-wider text-white/30">
              Persisted findings
            </div>
            <div className="mt-2 text-2xl font-semibold">
              {findings.length}
            </div>
          </div>

          <div className="rounded-2xl border border-white/10 p-4">
            <div className="text-xs uppercase tracking-wider text-white/30">
              Developer queue
            </div>
            <div className="mt-2 text-2xl font-semibold text-purple-300">
              {pending.length}
            </div>
          </div>

          <div className="rounded-2xl border border-white/10 p-4">
            <div className="text-xs uppercase tracking-wider text-white/30">
              Current run
            </div>
            <div className="mt-2 text-2xl font-semibold text-white/60">
              {result?.status || "—"}
            </div>
          </div>
        </div>

        {error && (
          <div className="mt-4 rounded-xl border border-red-400/20 bg-red-400/5 p-3 text-sm text-red-300">
            {error}
          </div>
        )}
      </div>

      <div className="rounded-3xl border border-white/10 bg-white/[0.025] p-6">
        <h3 className="text-lg font-semibold">
          Persisted canonical findings
        </h3>

        {findings.length === 0 ? (
          <div className="mt-5 rounded-2xl border border-white/10 bg-black/20 p-5 text-sm text-white/40">
            No persisted findings yet. Run a scan or a workforce assessment,
            then refresh.
          </div>
        ) : (
          <div className="mt-5 space-y-3">
            {findings.map((finding) => (
              <div
                key={finding.fingerprint}
                className="rounded-2xl border border-white/10 p-4"
              >
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div className="flex flex-wrap items-center gap-3">
                    <span
                      className={`rounded-md px-2 py-0.5 text-[11px] font-semibold ${severityClass(
                        finding.severity || "LOW"
                      )}`}
                    >
                      {finding.severity}
                    </span>

                    <span className="text-sm font-semibold">
                      [{finding.rule_id}] {finding.name}
                    </span>
                  </div>

                  <span
                    className={`rounded-full px-3 py-1 text-[11px] font-semibold ${workforceStateClass(
                      finding.validation_state === "corroborated"
                        ? "CORROBORATED"
                        : "REQUIRES_VALIDATION"
                    )}`}
                  >
                    {(finding.validation_state || "unvalidated").toUpperCase()}
                  </span>
                </div>

                <div className="mt-2 text-xs text-white/45">
                  {displayFile(finding.file || "")}:{finding.line}
                  {finding.code ? ` — ${finding.code}` : ""}
                </div>

                <div className="mt-2 text-[11px] text-white/35">
                  remediation: {finding.remediation_state || "open"} ·
                  verification: {finding.verification_state || "pending"} ·
                  sources:{" "}
                  {(finding.sources || [])
                    .map((source) => source.agent_id)
                    .join(", ") || "—"}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ─── ECC / Security Workforce (real capability map) ──────────

function EccWorkforcePanel({ apiUrl }: { apiUrl: string }) {
  const [capabilities, setCapabilities] = useState<WorkforceCapability[]>([]);
  const [findings, setFindings] = useState<CanonicalFinding[]>([]);
  const [error, setError] = useState("");

  async function refresh() {
    try {
      const [caps, found] = await Promise.all([
        fetch(`${apiUrl}/workforce/capabilities`),
        fetch(`${apiUrl}/workforce/findings`),
      ]);

      const capsJson = await caps.json();
      const foundJson = await found.json();

      setCapabilities(capsJson.capabilities || []);
      setFindings(foundJson.findings || []);
    } catch {
      setError(
        "Could not reach the PurpleGuard backend. Is the API running?"
      );
    }
  }

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const executable = capabilities.filter((cap) => cap.executable);
  const unavailable = capabilities.filter((cap) => !cap.executable);

  return (
    <div className="space-y-6">
      <div className="rounded-3xl border border-purple-500/20 bg-purple-500/5 p-6">
        <div className="text-xs font-semibold uppercase tracking-[0.18em] text-purple-300">
          ECC · Security Workforce
        </div>

        <h2 className="mt-2 text-2xl font-semibold">
          Real capabilities. Honest availability.
        </h2>

        <p className="mt-2 max-w-2xl text-sm leading-6 text-white/40">
          Every capability below executes through a real PurpleGuard engine. A
          capability whose engine primitive does not exist is reported
          UNAVAILABLE with the exact reason — never faked.
        </p>

        <div className="mt-5 grid grid-cols-3 gap-3">
          <div className="rounded-2xl border border-white/10 p-4">
            <div className="text-xs uppercase tracking-wider text-white/30">
              Total
            </div>
            <div className="mt-2 text-2xl font-semibold">
              {capabilities.length}
            </div>
          </div>

          <div className="rounded-2xl border border-white/10 p-4">
            <div className="text-xs uppercase tracking-wider text-white/30">
              Executable
            </div>
            <div className="mt-2 text-2xl font-semibold text-emerald-300">
              {executable.length}
            </div>
          </div>

          <div className="rounded-2xl border border-white/10 p-4">
            <div className="text-xs uppercase tracking-wider text-white/30">
              Unavailable
            </div>
            <div className="mt-2 text-2xl font-semibold text-white/50">
              {unavailable.length}
            </div>
          </div>
        </div>

        {error && (
          <div className="mt-4 rounded-xl border border-red-400/20 bg-red-400/5 p-3 text-sm text-red-300">
            {error}
          </div>
        )}
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <div className="rounded-3xl border border-white/10 bg-white/[0.025] p-6">
          <h3 className="text-lg font-semibold">Executable capabilities</h3>

          <div className="mt-4 space-y-2">
            {executable.map((cap) => (
              <div
                key={cap.agent_id}
                className="rounded-xl border border-white/10 p-3"
              >
                <div className="flex items-center justify-between gap-3">
                  <div className="text-sm font-semibold">{cap.agent_id}</div>
                  <span className="rounded-full bg-emerald-400/10 px-2 py-0.5 text-[10px] font-semibold text-emerald-300">
                    {cap.state}
                  </span>
                </div>

                <div className="mt-1 break-all text-[11px] text-white/35">
                  {cap.operation} · {cap.engine}
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="rounded-3xl border border-white/10 bg-white/[0.025] p-6">
          <h3 className="text-lg font-semibold">Unavailable capabilities</h3>

          <p className="mt-1 text-sm text-white/35">
            Reported honestly — no stub, no fake execution.
          </p>

          <div className="mt-4 space-y-2">
            {unavailable.map((cap) => (
              <div
                key={cap.agent_id}
                className="rounded-xl border border-white/10 p-3"
              >
                <div className="flex items-center justify-between gap-3">
                  <div className="text-sm font-semibold">{cap.agent_id}</div>
                  <span className="rounded-full bg-white/5 px-2 py-0.5 text-[10px] font-semibold text-white/40">
                    UNAVAILABLE
                  </span>
                </div>

                <div className="mt-1 text-[11px] text-white/35">
                  {cap.unavailable_reason}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="rounded-3xl border border-white/10 bg-white/[0.025] p-6">
        <h3 className="text-lg font-semibold">Workforce state</h3>

        <p className="mt-1 text-sm text-white/35">
          {findings.length} canonical finding(s) persisted from real engine
          runs.
        </p>

        <div className="mt-4 space-y-2">
          {findings.length === 0 ? (
            <div className="rounded-2xl border border-white/10 bg-black/20 p-5 text-sm text-white/40">
              No canonical findings yet. Run an assessment from the Hacker
              panel.
            </div>
          ) : (
            findings.map((finding) => (
              <div
                key={finding.fingerprint}
                className="flex items-center justify-between gap-3 rounded-xl border border-white/10 p-3"
              >
                <div className="min-w-0">
                  <div className="text-sm font-semibold">
                    [{finding.rule_id}] {finding.name}
                  </div>

                  <div className="mt-1 truncate text-[11px] text-white/35">
                    {displayFile(finding.file || "")}:{finding.line}
                  </div>
                </div>

                <span
                  className={`shrink-0 rounded-full px-2 py-0.5 text-[10px] font-semibold ${workforceStateClass(
                    finding.validation_state === "corroborated"
                      ? "CORROBORATED"
                      : "REQUIRES_VALIDATION"
                  )}`}
                >
                  {(finding.validation_state || "unvalidated").toUpperCase()}
                </span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
