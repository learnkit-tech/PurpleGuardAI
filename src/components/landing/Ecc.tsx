import { motion } from "framer-motion";
import {
  Bot,
  BrainCircuit,
  CheckCircle2,
  Code2,
  Database,
  Fingerprint,
  ScanSearch,
  Wrench,
  type LucideIcon,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Reveal } from "./Reveal";

interface FlowStep {
  icon: LucideIcon;
  label: string;
  sub: string;
  highlight?: boolean;
}

const FLOW: FlowStep[] = [
  { icon: Code2, label: "Developer", sub: "commits code to the repository" },
  { icon: ScanSearch, label: "PurpleGuard AI Scanner", sub: "static · secrets · cloud · supply chain" },
  { icon: Database, label: "Knowledge Graph", sub: "code, dependencies, cloud, and context" },
  { icon: BrainCircuit, label: "ECC Reasoning Engine", sub: "plans · coordinates · validates", highlight: true },
  { icon: Bot, label: "Security Agents", sub: "specialized investigators, in parallel" },
  { icon: Wrench, label: "Automatic Fixes", sub: "secure patches · verified pull requests" },
  { icon: CheckCircle2, label: "Verified Deployment", sub: "human-approved, shipped safely" },
];

const ECC_POINTS = [
  { icon: Fingerprint, text: "Plans investigations with full-stack context" },
  { icon: Bot, text: "Coordinates specialized AI agents in parallel" },
  { icon: CheckCircle2, text: "Validates every finding before it reaches you" },
  { icon: Wrench, text: "Generates secure, reviewable fixes" },
];

/** Animated pipeline: Developer → Scanner → Knowledge Graph → ECC → Agents → Fixes → Deploy */
function EccFlow() {
  return (
    <Reveal className="relative">
      <div
        aria-hidden="true"
        className="absolute -inset-8 rounded-[2.5rem] bg-violet-600/15 blur-3xl"
      />
      <div className="relative">
        {FLOW.map((step, i) => (
          <div key={step.label}>
            <motion.div
              initial={{ opacity: 0, x: 24 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: true, margin: "-60px" }}
              transition={{ duration: 0.55, delay: i * 0.12, ease: [0.22, 1, 0.36, 1] }}
              className={cn(
                "flex items-center gap-4 rounded-xl border px-4 py-3.5 backdrop-blur-md transition-colors",
                step.highlight
                  ? "border-violet-400/40 bg-violet-500/[0.12] shadow-[0_0_36px_rgba(124,58,237,0.25)]"
                  : "border-white/[0.08] bg-white/[0.03]",
              )}
            >
              <span
                className={cn(
                  "flex size-9 shrink-0 items-center justify-center rounded-lg border",
                  step.highlight
                    ? "border-violet-400/40 bg-violet-500/20 text-violet-200"
                    : "border-white/10 bg-white/[0.04] text-violet-300",
                )}
              >
                <step.icon className="size-4" />
              </span>
              <div className="min-w-0">
                <p
                  className={cn(
                    "text-sm font-medium",
                    step.highlight ? "text-violet-100" : "text-foreground",
                  )}
                >
                  {step.label}
                </p>
                <p className="truncate font-mono text-[11px] text-muted-foreground">
                  {step.sub}
                </p>
              </div>
            </motion.div>

            {i < FLOW.length - 1 && (
              <div className="relative mx-auto h-9 w-px overflow-hidden bg-gradient-to-b from-white/20 to-white/[0.04]">
                <motion.span
                  className="absolute left-1/2 size-1.5 -translate-x-1/2 rounded-full bg-violet-300 shadow-[0_0_12px_2px_rgba(167,139,250,0.9)]"
                  initial={{ top: "-10%" }}
                  animate={{ top: "110%" }}
                  transition={{
                    duration: 1.5,
                    delay: i * 0.35,
                    repeat: Infinity,
                    repeatType: "loop",
                    ease: "easeInOut",
                  }}
                />
              </div>
            )}
          </div>
        ))}
      </div>
    </Reveal>
  );
}

export function Ecc() {
  return (
    <section id="ecc" className="relative overflow-hidden py-24 sm:py-32">
      <div aria-hidden="true" className="absolute inset-0">
        <div className="absolute right-0 top-1/3 h-[420px] w-[420px] rounded-full bg-violet-600/15 blur-[130px]" />
        <div className="absolute left-0 bottom-0 h-[300px] w-[300px] rounded-full bg-purple-500/10 blur-[120px]" />
      </div>

      <div className="relative mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="grid items-center gap-16 lg:grid-cols-2 lg:gap-20">
          {/* Copy */}
          <div>
            <Reveal>
              <p className="mb-5 inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.03] px-3 py-1 font-mono text-[11px] uppercase tracking-[0.2em] text-violet-300">
                <span className="size-1 rounded-full bg-violet-400 shadow-[0_0_8px_1px_rgba(167,139,250,0.9)]" />
                Intelligence Layer
              </p>
              <h2 className="text-3xl font-semibold tracking-tight text-foreground sm:text-4xl lg:text-[2.6rem] lg:leading-[1.15]">
                Enterprise Cyber Command <span className="text-violet-300">(ECC)</span>
              </h2>
            </Reveal>

            <Reveal delay={0.08}>
              <p className="mt-6 text-base leading-relaxed text-muted-foreground">
                ECC is the intelligence layer behind PurpleGuard AI. It plans
                investigations, coordinates specialized AI agents, validates
                findings, generates secure fixes, verifies remediation, and
                continuously improves its reasoning.
              </p>
              <p className="mt-4 text-base leading-relaxed text-muted-foreground">
                ECC functions like an autonomous AI security operations center —
                assisting developers and security teams instead of replacing
                them.
              </p>
            </Reveal>

            <div className="mt-8 grid gap-3 sm:grid-cols-2">
              {ECC_POINTS.map((point, i) => (
                <Reveal key={point.text} delay={0.15 + i * 0.06}>
                  <div className="flex items-start gap-2.5 rounded-lg border border-white/[0.06] bg-white/[0.02] px-3.5 py-3 transition-colors hover:border-violet-400/25 hover:bg-white/[0.04]">
                    <point.icon className="mt-0.5 size-4 shrink-0 text-violet-300" />
                    <p className="text-sm leading-snug text-foreground/90">
                      {point.text}
                    </p>
                  </div>
                </Reveal>
              ))}
            </div>
          </div>

          {/* Animated architecture */}
          <EccFlow />
        </div>
      </div>
    </section>
  );
}
