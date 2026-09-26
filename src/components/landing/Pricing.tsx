import { Check } from "lucide-react";
import { Link } from "react-router";
import { cn } from "@/lib/utils";
import { PRICING_PLANS } from "./data";
import { Reveal } from "./Reveal";
import { SectionHeader } from "./SectionHeader";

export function Pricing() {
  return (
    <section id="pricing" className="relative overflow-hidden py-24 sm:py-32">
      <div aria-hidden="true" className="absolute inset-0">
        <div className="absolute left-1/2 top-1/3 h-[360px] w-[760px] -translate-x-1/2 rounded-full bg-violet-600/10 blur-[130px]" />
        <div className="absolute bottom-0 right-10 h-[260px] w-[260px] rounded-full bg-cyan-400/[0.05] blur-[110px]" />
      </div>

      <div className="relative mx-auto max-w-6xl px-4 sm:px-6 lg:px-8">
        <SectionHeader
          eyebrow="Pricing"
          title="Pricing that scales with your estate"
          description="No per-seat fees for agents. Plans scale with repositories and cloud assets — start free, and grow as your posture does."
        />

        <div className="mt-14 grid gap-5 lg:grid-cols-3">
          {PRICING_PLANS.map((plan, i) => (
            <Reveal key={plan.name} delay={i * 0.08} className="h-full">
              <div
                className={cn(
                  "relative flex h-full flex-col rounded-2xl border p-7",
                  plan.featured
                    ? "border-violet-400/40 bg-gradient-to-b from-violet-500/[0.12] to-transparent shadow-[0_0_60px_-12px_rgba(124,58,237,0.45)]"
                    : "border-white/[0.08] bg-white/[0.02]",
                )}
              >
                {plan.featured && (
                  <span className="absolute -top-3 left-1/2 -translate-x-1/2 rounded-full border border-violet-400/40 bg-violet-500/20 px-3 py-1 font-mono text-[10px] uppercase tracking-[0.16em] text-violet-200">
                    Most popular
                  </span>
                )}
                <h3 className="text-lg font-semibold tracking-tight text-foreground">
                  {plan.name}
                </h3>
                <p className="mt-1 text-sm text-muted-foreground">{plan.tagline}</p>
                <div className="mt-6 flex items-baseline gap-2">
                  <span className="font-mono text-4xl font-semibold tracking-tight text-foreground">
                    {plan.price}
                  </span>
                  <span className="font-mono text-xs text-muted-foreground">
                    {plan.cadence}
                  </span>
                </div>
                <ul className="mt-7 flex-1 space-y-3">
                  {plan.features.map((feature) => (
                    <li
                      key={feature}
                      className="flex items-start gap-2.5 text-sm text-foreground/85"
                    >
                      <span className="mt-0.5 flex size-4 shrink-0 items-center justify-center rounded-full bg-violet-500/25">
                        <Check className="size-2.5 text-violet-200" />
                      </span>
                      {feature}
                    </li>
                  ))}
                </ul>
                <Link
                  to="/auth"
                  className={cn(
                    "mt-8 inline-flex items-center justify-center rounded-lg px-4 py-2.5 text-sm font-medium transition-all",
                    plan.featured
                      ? "bg-violet-600 text-white shadow-[0_0_28px_rgba(124,58,237,0.45)] hover:bg-violet-500 hover:shadow-[0_0_36px_rgba(124,58,237,0.6)]"
                      : "border border-white/10 bg-white/[0.03] text-foreground hover:border-white/20 hover:bg-white/[0.06]",
                  )}
                >
                  {plan.cta}
                </Link>
              </div>
            </Reveal>
          ))}
        </div>

        <Reveal delay={0.18}>
          <div className="mt-6 flex flex-col items-center justify-between gap-5 rounded-2xl border border-white/[0.08] bg-gradient-to-r from-violet-500/[0.08] via-transparent to-cyan-400/[0.05] px-7 py-6 sm:flex-row">
            <div>
              <h3 className="text-base font-semibold tracking-tight text-foreground">
                Enterprise — PurpleGuard for global teams
              </h3>
              <p className="mt-1 text-sm text-muted-foreground">
                Dedicated ECC infrastructure, on-premise or air-gapped
                deployment, SSO/SAML, private networking, and support SLAs.
              </p>
            </div>
            <a
              href="#contact"
              className="shrink-0 rounded-lg border border-white/10 bg-white/[0.03] px-5 py-2.5 text-sm font-medium text-foreground transition-colors hover:border-violet-400/40 hover:bg-violet-500/10 hover:text-violet-200"
            >
              Talk to sales
            </a>
          </div>
        </Reveal>
      </div>
    </section>
  );
}
