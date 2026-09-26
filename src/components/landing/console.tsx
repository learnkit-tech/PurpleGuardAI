import { motion } from "framer-motion";
import { useEffect, useId, useState } from "react";
import { cn } from "@/lib/utils";

export type Tone = "violet" | "emerald" | "amber" | "cyan" | "rose";

/** Cycles 0 → length-1 forever. Callers use it to rotate feed content. */
export function useTicker(length: number, intervalMs: number) {
  const [tick, setTick] = useState(0);
  useEffect(() => {
    if (length <= 0) return;
    const id = window.setInterval(() => {
      setTick((t) => (t + 1) % length);
    }, intervalMs);
    return () => window.clearInterval(id);
  }, [length, intervalMs]);
  return tick;
}

const TONE_BG: Record<Tone, string> = {
  violet: "bg-violet-400",
  emerald: "bg-emerald-400",
  amber: "bg-amber-400",
  cyan: "bg-cyan-300",
  rose: "bg-rose-400",
};

export function StatusDot({ tone, className }: { tone: Tone; className?: string }) {
  return (
    <span className={cn("relative inline-flex size-2 shrink-0", className)}>
      <span
        className={cn(
          "absolute inline-flex h-full w-full animate-ping rounded-full opacity-50",
          TONE_BG[tone],
        )}
      />
      <span
        className={cn("relative inline-flex size-2 rounded-full", TONE_BG[tone])}
      />
    </span>
  );
}

interface ScoreRingProps {
  score: number;
  size?: number;
  strokeWidth?: number;
  label?: string;
  className?: string;
}

/** SVG score ring with an animated fill. */
export function ScoreRing({
  score,
  size = 108,
  strokeWidth = 7,
  label = "Security score",
  className,
}: ScoreRingProps) {
  const gradientId = useId();
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference * (1 - score / 100);

  return (
    <div
      className={cn("relative shrink-0", className)}
      style={{ width: size, height: size }}
    >
      <svg width={size} height={size} className="-rotate-90">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="currentColor"
          className="text-white/10"
          strokeWidth={strokeWidth}
        />
        <motion.circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={`url(#${gradientId})`}
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          strokeDasharray={circumference}
          initial={{ strokeDashoffset: circumference }}
          whileInView={{ strokeDashoffset: offset }}
          viewport={{ once: true }}
          transition={{ duration: 1.8, ease: [0.22, 1, 0.36, 1] }}
        />
        <defs>
          <linearGradient id={gradientId} x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#a78bfa" />
            <stop offset="100%" stopColor="#7c3aed" />
          </linearGradient>
        </defs>
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="font-mono text-[1.65rem] font-semibold leading-none tracking-tight text-foreground">
          {score}
        </span>
        <span className="mt-1 max-w-[80px] text-center text-[9px] font-medium uppercase tracking-[0.14em] text-muted-foreground">
          {label}
        </span>
      </div>
    </div>
  );
}

const GRAPH_NODES = [
  { x: 42, y: 22, tone: "cyan" },
  { x: 128, y: 44, tone: "violet" },
  { x: 56, y: 78, tone: "violet" },
  { x: 138, y: 102, tone: "cyan" },
  { x: 62, y: 128, tone: "violet" },
  { x: 128, y: 152, tone: "rose" },
  { x: 92, y: 178, tone: "amber" },
] as const;

const GRAPH_EDGES: Array<[number, number]> = [
  [0, 1],
  [0, 2],
  [1, 3],
  [2, 4],
  [3, 5],
  [4, 6],
  [1, 4],
];

/** Dependency-graph style visualization with data flowing along edges. */
export function ThreatGraph({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 180 200"
      role="img"
      aria-label="Threat graph showing connections between monitored services"
      className={cn("h-full w-full", className)}
    >
      {GRAPH_EDGES.map(([a, b], i) => {
        const from = GRAPH_NODES[a];
        const to = GRAPH_NODES[b];
        return (
          <motion.line
            key={i}
            x1={from.x}
            y1={from.y}
            x2={to.x}
            y2={to.y}
            stroke="currentColor"
            className="text-white/15"
            strokeWidth={1}
            strokeDasharray="3 6"
            animate={{ strokeDashoffset: [0, -18] }}
            transition={{
              duration: 1.3 + (i % 3) * 0.3,
              repeat: Infinity,
              ease: "linear",
            }}
          />
        );
      })}
      {GRAPH_NODES.map((n, i) => (
        <g key={i}>
          <motion.circle
            cx={n.x}
            cy={n.y}
            r={3.5}
            fill={n.tone === "cyan" ? "#22d3ee" : n.tone === "rose" ? "#fb7185" : n.tone === "amber" ? "#fbbf24" : "#a78bfa"}
            animate={{ opacity: [0.55, 1, 0.55] }}
            transition={{
              duration: 2.2,
              delay: i * 0.25,
              repeat: Infinity,
              ease: "easeInOut",
            }}
          />
          <circle
            cx={n.x}
            cy={n.y}
            r={7}
            fill="none"
            stroke={n.tone === "cyan" ? "#22d3ee" : "#a78bfa"}
            strokeOpacity={0.18}
            strokeWidth={1}
          />
        </g>
      ))}
    </svg>
  );
}
