import { AnimatePresence, motion } from "framer-motion";
import { ArrowRight, CheckCircle2, Play, ScanEye } from "lucide-react";
import { Link } from "react-router";
import { Particles } from "./Particles";
import { ScoreRing, StatusDot, ThreatGraph, useTicker, type Tone } from "./console";
import { HERO_ACTIVITY } from "./data";

const EASE = [0.22, 1, 0.36, 1] as const;

const CONTAINER = {
  hidden: {},
  show: { transition: { staggerChildren: 0.12, delayChildren: 0.1 } },
};

const ITEM = {
  hidden: { opacity: 0, y: 24 },
  show: { opacity: 1, y: 0, transition: { duration: 0.7, ease: EASE } },
};

function HeroConsole() {
  const tick = useTicker(HERO_ACTIVITY.length, 2400);
  // Show a sliding window of 4 activities (wrap by duplicating the array).
  const windowed = [...HERO_ACTIVITY, ...HERO_ACTIVITY].slice(tick, tick + 4);

  return (
    <motion.div
      initial={{ opacity: 0, y: 32, scale: 0.98 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      transition={{ duration: 0.9, delay: 0.35, ease: EASE }}
      className="relative"
    >
      {/* Glow behind the panel */}
      <div
        aria-hidden="true"
        className="absolute -inset-6 rounded-[2rem] bg-gradient-to-br from-violet-500/25 via-purple-600/10 to-cyan-400/10 blur-2xl"
      />

      <div className="relative overflow-hidden rounded-2xl border border-white/10 bg-[#0c0b14]/90 shadow-2xl shadow-violet-950/50 backdrop-blur-xl">
        {/* Window chrome */}
        <div className="flex items-center justify-between border-b border-white/[0.07] px-4 py-3">
          <div className="flex items-center gap-1.5">
            <span className="size-2.5 rounded-full bg-white/15" />
            <span className="size-2.5 rounded-full bg-white/15" />
            <span className="size-2.5 rounded-full bg-white/15" />
          </div>
          <p className="font-mono text-[11px] tracking-wide text-muted-foreground">
            purpleguard — ECC console
          </p>
          <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-400/25 bg-emerald-400/10 px-2 py-0.5 font-mono text-[10px] font-medium uppercase tracking-wider text-emerald-300">
            <span className="size-1.5 animate-pulse rounded-full bg-emerald-400" />
            Live
          </span>
        </div>

        {/* Console body */}
        <div className="grid gap-4 p-4 sm:grid-cols-[auto_1fr]">
          {/* Score + stats */}
          <div className="flex flex-col items-center gap-4 rounded-xl border border-white/[0.06] bg-white/[0.02] p-4">
            <ScoreRing score={94} size={120} />
            <div className="w-full space-y-2 border-t border-white/[0.06] pt-3">
              {[
                { k: "Findings", v: "247" },
                { k: "Fixed", v: "236" },
                { k: "Auto-fixed", v: "95%" },
              ].map((row) => (
                <div
                  key={row.k}
                  className="flex items-center justify-between font-mono text-[11px]"
                >
                  <span className="text-muted-foreground">{row.k}</span>
                  <span className="font-medium text-foreground">{row.v}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Threat graph */}
          <div className="relative min-h-[200px] overflow-hidden rounded-xl border border-white/[0.06] bg-white/[0.02] p-3">
            <div className="absolute inset-0 bg-grid opacity-40" />
            <ThreatGraph className="relative h-full" />
          </div>
        </div>

        {/* Activity feed */}
        <div className="border-t border-white/[0.07] bg-black/20 px-4 py-3">
          <p className="mb-2.5 font-mono text-[10px] uppercase tracking-[0.18em] text-muted-foreground">
            Live activity
          </p>
          <ul className="space-y-2">
            <AnimatePresence initial={false} mode="popLayout">
              {windowed.map((a) => (
                <motion.li
                  key={a.id}
                  layout
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: 10 }}
                  transition={{ duration: 0.35 }}
                  className="flex items-center gap-2.5 font-mono text-[11px] text-muted-foreground"
                >
                  <StatusDot tone={a.tone as Tone} />
                  <span className="truncate">{a.text}</span>
                </motion.li>
              ))}
            </AnimatePresence>
          </ul>
        </div>
      </div>

      {/* Floating chips */}
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 1.1, duration: 0.6, ease: EASE }}
        className="absolute -left-4 top-24 hidden items-center gap-2 rounded-xl border border-white/10 bg-background/90 px-3.5 py-2.5 shadow-xl shadow-violet-950/40 backdrop-blur-md sm:flex lg:-left-8"
      >
        <CheckCircle2 className="size-4 text-emerald-400" />
        <div>
          <p className="text-xs font-medium text-foreground">Fix verified</p>
          <p className="font-mono text-[10px] text-muted-foreground">
            CVE-2024-47176 · merged
          </p>
        </div>
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 1.35, duration: 0.6, ease: EASE }}
        className="absolute -right-3 bottom-16 hidden items-center gap-2 rounded-xl border border-white/10 bg-background/90 px-3.5 py-2.5 shadow-xl shadow-violet-950/40 backdrop-blur-md sm:flex lg:-right-6"
      >
        <ScanEye className="size-4 text-violet-300" />
        <div>
          <p className="text-xs font-medium text-foreground">Agent dispatched</p>
          <p className="font-mono text-[10px] text-muted-foreground">
            sentinel-04 · supply-chain
          </p>
        </div>
      </motion.div>
    </motion.div>
  );
}

export function Hero() {
  return (
    <section
      id="top"
      className="relative overflow-hidden pb-24 pt-32 sm:pb-32 sm:pt-40"
    >
      {/* Background layers */}
      <div aria-hidden="true" className="absolute inset-0">
        <div className="absolute inset-0 bg-grid opacity-[0.5] [mask-image:radial-gradient(ellipse_70%_60%_at_50%_0%,black,transparent)]" />
        <div className="absolute -top-40 left-1/2 h-[520px] w-[820px] -translate-x-1/2 rounded-full bg-violet-600/20 blur-[130px] animate-drift" />
        <div className="absolute top-40 -right-40 h-[380px] w-[380px] rounded-full bg-purple-500/15 blur-[110px]" />
        <div className="absolute top-64 -left-40 h-[320px] w-[320px] rounded-full bg-cyan-400/[0.07] blur-[110px]" />
        <Particles count={22} />
      </div>

      <div className="relative mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="grid items-center gap-16 lg:grid-cols-[1.05fr_1fr] lg:gap-12">
          {/* Copy */}
          <motion.div variants={CONTAINER} initial="hidden" animate="show">
            <motion.p
              variants={ITEM}
              className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.03] px-3.5 py-1.5 font-mono text-[11px] uppercase tracking-[0.18em] text-violet-300"
            >
              <span className="size-1.5 rounded-full bg-violet-400 shadow-[0_0_10px_2px_rgba(167,139,250,0.8)]" />
              ECC · Enterprise Cyber Command — Early access
            </motion.p>

            <motion.h1
              variants={ITEM}
              className="mt-6 text-4xl font-semibold leading-[1.08] tracking-tighter text-white sm:text-6xl lg:text-[4.25rem]"
            >
              The Future of{" "}
              <span className="bg-gradient-to-r from-violet-300 via-violet-400 to-purple-500 bg-clip-text text-transparent">
                Autonomous
                <br className="hidden sm:block" /> Cybersecurity.
              </span>
            </motion.h1>

            <motion.p
              variants={ITEM}
              className="mt-6 max-w-xl text-base leading-relaxed text-muted-foreground sm:text-lg"
            >
              PurpleGuard AI continuously detects, understands, prioritizes, and
              remediates security risks while ECC coordinates intelligent AI
              agents that reason, investigate, and respond automatically.
            </motion.p>

            <motion.div variants={ITEM} className="mt-9 flex flex-wrap items-center gap-4">
              <Link
                to="/auth"
                className="group inline-flex items-center gap-2 rounded-lg bg-violet-600 px-5 py-3 text-sm font-medium text-white shadow-[0_0_32px_rgba(124,58,237,0.45)] transition-all hover:bg-violet-500 hover:shadow-[0_0_44px_rgba(124,58,237,0.65)]"
              >
                Request Early Access
                <ArrowRight className="size-4 transition-transform group-hover:translate-x-0.5" />
              </Link>
              <a
                href="#preview"
                className="group inline-flex items-center gap-2.5 rounded-lg border border-white/10 bg-white/[0.03] px-5 py-3 text-sm font-medium text-foreground transition-colors hover:border-white/20 hover:bg-white/[0.06]"
              >
                <span className="flex size-6 items-center justify-center rounded-full border border-white/20 transition-colors group-hover:border-violet-300 group-hover:bg-violet-500/20">
                  <Play className="size-3 fill-current text-violet-300" />
                </span>
                Watch Demo
              </a>
            </motion.div>

            <motion.p
              variants={ITEM}
              className="mt-10 font-mono text-[11px] uppercase tracking-[0.22em] text-muted-foreground/80"
            >
              Scans every commit
              <span className="mx-2 text-violet-400/60">·</span>
              Understands every service
              <span className="mx-2 text-violet-400/60">·</span>
              Fixes in minutes
            </motion.p>
          </motion.div>

          {/* Console */}
          <HeroConsole />
        </div>
      </div>
    </section>
  );
}
