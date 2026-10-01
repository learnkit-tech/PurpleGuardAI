import { motion } from "framer-motion";
import { Reveal } from "./Reveal";
import { SectionHeader } from "./SectionHeader";
import { ROADMAP } from "./data";
import { cn } from "@/lib/utils";

export function Roadmap() {
  return (
    <section id="roadmap" className="relative py-24 sm:py-32">
      <div className="mx-auto max-w-4xl px-4 sm:px-6 lg:px-8">
        <SectionHeader
          eyebrow="Roadmap"
          title="The path to autonomous defense"
          description="A deliberate progression from smarter scanning to a global AI cyber defense network."
        />

        <div className="relative mt-16 pl-10 sm:pl-14">
          {/* Timeline spine */}
          <motion.div
            aria-hidden="true"
            className="absolute left-4 top-2 bottom-2 w-px origin-top bg-gradient-to-b from-violet-400 via-violet-500/40 to-transparent sm:left-5"
            initial={{ scaleY: 0 }}
            whileInView={{ scaleY: 1 }}
            viewport={{ once: true, margin: "-100px" }}
            transition={{ duration: 1.4, ease: [0.22, 1, 0.36, 1] }}
          />

          <ol className="space-y-12">
            {ROADMAP.map((item, i) => (
              <li key={item.year} className="relative">
                {/* Node */}
                <span
                  className={cn(
                    "absolute -left-10 top-1.5 flex size-4 items-center justify-center rounded-full border sm:-left-14",
                    i === 0
                      ? "border-violet-300 bg-violet-500/40 shadow-[0_0_14px_rgba(167,139,250,0.7)]"
                      : "border-violet-400/40 bg-background",
                  )}
                >
                  <span
                    className={cn(
                      "size-1.5 rounded-full",
                      i === 0 ? "bg-violet-200" : "bg-violet-400/70",
                    )}
                  />
                </span>

                <Reveal delay={i * 0.05}>
                  <div className="flex flex-wrap items-baseline gap-x-4 gap-y-1">
                    <span className="font-mono text-sm font-semibold tracking-[0.2em] text-violet-300">
                      {item.year}
                    </span>
                    {i === 0 && (
                      <span className="rounded-full border border-violet-400/30 bg-violet-500/15 px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider text-violet-200">
                        Now
                      </span>
                    )}
                    <h3 className="text-lg font-semibold tracking-tight text-foreground">
                      {item.title}
                    </h3>
                  </div>
                  <p className="mt-2 max-w-xl text-sm leading-relaxed text-muted-foreground">
                    {item.description}
                  </p>
                </Reveal>
              </li>
            ))}
          </ol>
        </div>
      </div>
    </section>
  );
}
