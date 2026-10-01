import { ArrowRight } from "lucide-react";
import { Link } from "react-router";
import { Reveal } from "./Reveal";

export function Vision() {
  return (
    <section id="vision" className="relative overflow-hidden py-28 sm:py-36">
      {/* Hairline dividers */}
      <div aria-hidden="true" className="absolute inset-x-0 top-0 border-t border-white/[0.06]" />
      <div aria-hidden="true" className="absolute inset-x-0 bottom-0 border-t border-white/[0.06]" />

      <div aria-hidden="true" className="absolute inset-0">
        <div className="absolute left-1/2 top-1/2 h-[440px] w-[880px] -translate-x-1/2 -translate-y-1/2 rounded-full bg-violet-600/[0.13] blur-[140px]" />
      </div>

      <div className="relative mx-auto max-w-4xl px-4 text-center sm:px-6 lg:px-8">
        <Reveal>
          <p className="mb-6 inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.03] px-3 py-1 font-mono text-[11px] uppercase tracking-[0.2em] text-violet-300">
            <span className="size-1 rounded-full bg-violet-400 shadow-[0_0_8px_1px_rgba(167,139,250,0.9)]" />
            Vision
          </p>
          <h2 className="text-3xl font-semibold leading-tight tracking-tight text-white sm:text-5xl lg:text-[3.4rem] lg:leading-[1.12]">
            Changing the Course of{" "}
            <span className="bg-gradient-to-r from-violet-300 via-violet-400 to-cyan-300 bg-clip-text text-transparent">
              Cybersecurity
            </span>
          </h2>
        </Reveal>

        <Reveal delay={0.1}>
          <p className="mx-auto mt-7 max-w-2xl text-base leading-relaxed text-muted-foreground sm:text-lg">
            PurpleGuard AI is building the next generation of cybersecurity where
            intelligent AI agents don&apos;t simply detect vulnerabilities — they
            understand them, collaborate, explain their reasoning, generate
            secure fixes, verify those fixes, and continuously learn to defend
            modern software, cloud infrastructure, and AI systems.
          </p>
        </Reveal>

        <Reveal delay={0.18}>
          <div className="mt-10 flex flex-wrap items-center justify-center gap-4">
            <Link
              to="/auth"
              className="group inline-flex items-center gap-2 rounded-lg bg-violet-600 px-6 py-3 text-sm font-medium text-white shadow-[0_0_32px_rgba(124,58,237,0.45)] transition-all hover:bg-violet-500 hover:shadow-[0_0_44px_rgba(124,58,237,0.65)]"
            >
              Request Early Access
              <ArrowRight className="size-4 transition-transform group-hover:translate-x-0.5" />
            </Link>
            <a
              href="#roadmap"
              className="rounded-lg border border-white/10 bg-white/[0.03] px-6 py-3 text-sm font-medium text-foreground transition-colors hover:border-white/20 hover:bg-white/[0.06]"
            >
              View the roadmap
            </a>
          </div>
        </Reveal>
      </div>
    </section>
  );
}
