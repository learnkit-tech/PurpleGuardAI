import { motion } from "framer-motion";
import { useMemo } from "react";
import { cn } from "@/lib/utils";

function mulberry32(seed: number) {
  return () => {
    seed |= 0;
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const COLORS = ["#a78bfa", "#7c3aed", "#22d3ee", "#c4b5fd", "#e4e4e7"];

interface ParticlesProps {
  count?: number;
  className?: string;
}

/** Ambient glowing particles that drift slowly — decorative only. */
export function Particles({ count = 18, className }: ParticlesProps) {
  const particles = useMemo(() => {
    const rand = mulberry32(20260805);
    return Array.from({ length: count }, (_, i) => ({
      id: i,
      left: rand() * 100,
      top: rand() * 100,
      size: 2 + rand() * 3.5,
      delay: rand() * 6,
      duration: 9 + rand() * 11,
      color: COLORS[Math.floor(rand() * COLORS.length)],
    }));
  }, [count]);

  return (
    <div
      aria-hidden="true"
      className={cn("pointer-events-none absolute inset-0 overflow-hidden", className)}
    >
      {particles.map((p) => (
        <motion.span
          key={p.id}
          className="absolute rounded-full"
          style={{
            left: `${p.left}%`,
            top: `${p.top}%`,
            width: p.size,
            height: p.size,
            backgroundColor: p.color,
            boxShadow: `0 0 ${p.size * 4}px ${p.color}`,
          }}
          animate={{ y: [0, -46, 0], opacity: [0.1, 0.65, 0.1] }}
          transition={{
            duration: p.duration,
            delay: p.delay,
            repeat: Infinity,
            ease: "easeInOut",
          }}
        />
      ))}
    </div>
  );
}
