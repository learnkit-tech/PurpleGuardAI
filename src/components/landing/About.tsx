import { Reveal } from "./Reveal";
import { SectionHeader } from "./SectionHeader";
import { CAPABILITIES } from "./data";

export function About() {
  return (
    <section id="platform" className="relative py-24 sm:py-32">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <SectionHeader
          eyebrow="Platform"
          title="What is PurpleGuard AI?"
          description="An AI-native cybersecurity platform that scans everything you ship — code, secrets, dependencies, cloud infrastructure — and turns findings into reasoned, verified fixes. One platform, from first commit to production posture."
        />

        <div className="mt-14 grid gap-px overflow-hidden rounded-2xl border border-white/[0.08] bg-white/[0.06] sm:grid-cols-2 lg:grid-cols-3">
          {CAPABILITIES.map((cap, i) => (
            <Reveal key={cap.title} delay={(i % 3) * 0.06} className="h-full">
              <div className="group flex h-full flex-col gap-3 bg-background p-6 transition-colors duration-300 hover:bg-white/[0.03]">
                <span className="flex size-9 items-center justify-center rounded-lg border border-white/10 bg-white/[0.03] text-violet-300 transition-colors group-hover:border-violet-400/40 group-hover:text-violet-200">
                  <cap.icon className="size-4" />
                </span>
                <h3 className="text-sm font-medium text-foreground">
                  {cap.title}
                </h3>
                <p className="text-sm leading-relaxed text-muted-foreground">
                  {cap.description}
                </p>
              </div>
            </Reveal>
          ))}
        </div>
      </div>
    </section>
  );
}
