import { Reveal } from "./Reveal";
import { SectionHeader } from "./SectionHeader";
import { SOLUTIONS } from "./data";

export function Solutions() {
  return (
    <section id="solutions" className="relative py-24 sm:py-32">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <SectionHeader
          eyebrow="Solutions"
          title="Security that fits how you ship"
          description="From a two-person startup to a global bank, the same intelligence layer adapts to your stack, your scale, and your compliance obligations."
        />

        <div className="mt-14 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {SOLUTIONS.map((solution, i) => (
            <Reveal key={solution.title} delay={(i % 3) * 0.07} className="h-full">
              <div className="group relative h-full overflow-hidden rounded-xl border border-white/[0.08] bg-white/[0.02] p-6 transition-all duration-300 hover:-translate-y-1 hover:border-violet-400/30 hover:bg-white/[0.04]">
                <span className="absolute right-5 top-5 font-mono text-[11px] text-white/20 transition-colors group-hover:text-violet-300/60">
                  {String(i + 1).padStart(2, "0")}
                </span>
                <span className="flex size-10 items-center justify-center rounded-lg border border-white/10 bg-white/[0.03] text-violet-300 transition-colors duration-300 group-hover:border-violet-400/40 group-hover:bg-violet-500/10 group-hover:text-violet-200">
                  <solution.icon className="size-4" />
                </span>
                <h3 className="mt-4 text-[15px] font-medium text-foreground">
                  {solution.title}
                </h3>
                <p className="mt-1.5 text-sm leading-relaxed text-muted-foreground">
                  {solution.description}
                </p>
              </div>
            </Reveal>
          ))}
        </div>
      </div>
    </section>
  );
}
