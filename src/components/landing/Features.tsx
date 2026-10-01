import { Reveal } from "./Reveal";
import { SectionHeader } from "./SectionHeader";
import { FEATURES } from "./data";

export function Features() {
  return (
    <section id="technology" className="relative py-24 sm:py-32">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <SectionHeader
          eyebrow="Technology"
          title="One platform, twelve layers of defense"
          description="Every capability is native — no bolt-ons, no glue code. PurpleGuard AI scans, ECC reasons, agents act, and the loop closes automatically."
        />

        <div className="mt-14 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {FEATURES.map((feature, i) => (
            <Reveal key={feature.title} delay={(i % 3) * 0.07} className="h-full">
              <div className="group relative h-full overflow-hidden rounded-xl border border-white/[0.08] bg-gradient-to-b from-white/[0.04] to-transparent p-6 transition-all duration-300 hover:-translate-y-1 hover:border-violet-400/30 hover:shadow-[0_8px_40px_-12px_rgba(124,58,237,0.35)]">
                <div
                  aria-hidden="true"
                  className="absolute -right-16 -top-16 size-32 rounded-full bg-violet-500/10 opacity-0 blur-2xl transition-opacity duration-500 group-hover:opacity-100"
                />
                <span className="flex size-10 items-center justify-center rounded-lg border border-white/10 bg-white/[0.03] text-violet-300 transition-colors duration-300 group-hover:border-violet-400/40 group-hover:bg-violet-500/10 group-hover:text-violet-200">
                  <feature.icon className="size-4 text-inherit" />
                </span>
                <h3 className="mt-4 text-[15px] font-medium text-foreground">
                  {feature.title}
                </h3>
                <p className="mt-1.5 text-sm leading-relaxed text-muted-foreground">
                  {feature.description}
                </p>
              </div>
            </Reveal>
          ))}
        </div>
      </div>
    </section>
  );
}
