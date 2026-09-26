import { ArrowRight, Mail, Radar, ShieldCheck, Sparkles } from "lucide-react";
import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router";
import { cn } from "@/lib/utils";
import { Reveal } from "./Reveal";

const CHANNELS = [
  {
    icon: Mail,
    label: "Early access",
    value: "early-access@purpleguard.ai",
    href: "mailto:early-access@purpleguard.ai",
  },
  {
    icon: ShieldCheck,
    label: "Security disclosures",
    value: "security@purpleguard.ai",
    href: "mailto:security@purpleguard.ai",
  },
  {
    icon: Radar,
    label: "Status",
    value: "All systems operational",
    href: "#top",
  },
];

export function Contact() {
  const navigate = useNavigate();
  const [email, setEmail] = useState("");

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    navigate("/auth");
  };

  return (
    <section id="contact" className="relative overflow-hidden py-24 sm:py-32">
      <div aria-hidden="true" className="absolute inset-0">
        <div className="absolute left-1/2 top-1/2 h-[360px] w-[820px] -translate-x-1/2 -translate-y-1/2 rounded-full bg-violet-600/10 blur-[140px]" />
      </div>

      <div className="relative mx-auto max-w-6xl px-4 sm:px-6 lg:px-8">
        <div className="grid items-center gap-14 lg:grid-cols-2 lg:gap-20">
          {/* Copy */}
          <div>
            <Reveal>
              <p className="mb-5 inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.03] px-3 py-1 font-mono text-[11px] uppercase tracking-[0.2em] text-violet-300">
                <span className="size-1 rounded-full bg-violet-400 shadow-[0_0_8px_1px_rgba(167,139,250,0.9)]" />
                Contact
              </p>
              <h2 className="text-3xl font-semibold tracking-tight text-foreground sm:text-4xl lg:text-[2.6rem] lg:leading-[1.15]">
                Join the early access{" "}
                <span className="bg-gradient-to-r from-violet-300 to-violet-500 bg-clip-text text-transparent">
                  program
                </span>
              </h2>
            </Reveal>
            <Reveal delay={0.08}>
              <p className="mt-6 max-w-lg text-base leading-relaxed text-muted-foreground">
                PurpleGuard AI is onboarding teams in batches. Tell us where to
                send your invitation — we&apos;ll reach out within two business
                days with next steps and a personalized onboarding plan.
              </p>
            </Reveal>

            <div className="mt-9 space-y-4">
              {CHANNELS.map((channel, i) => (
                <Reveal key={channel.label} delay={0.14 + i * 0.06}>
                  <a
                    href={channel.href}
                    className="group flex items-center gap-3.5 rounded-xl border border-white/[0.06] bg-white/[0.02] px-4 py-3.5 transition-colors hover:border-violet-400/25 hover:bg-white/[0.04]"
                  >
                    <span className="flex size-9 shrink-0 items-center justify-center rounded-lg border border-white/10 bg-white/[0.03] text-violet-300 transition-colors group-hover:border-violet-400/40 group-hover:text-violet-200">
                      <channel.icon className="size-4" />
                    </span>
                    <div className="min-w-0">
                      <p className="text-[11px] font-medium uppercase tracking-[0.14em] text-muted-foreground">
                        {channel.label}
                      </p>
                      <p className="truncate text-sm font-medium text-foreground">
                        {channel.value}
                      </p>
                    </div>
                  </a>
                </Reveal>
              ))}
            </div>
          </div>

          {/* Request form */}
          <Reveal delay={0.1}>
            <div className="relative">
              <div
                aria-hidden="true"
                className="absolute -inset-4 rounded-[2rem] bg-gradient-to-br from-violet-600/20 to-cyan-400/10 blur-2xl"
              />
              <form
                onSubmit={handleSubmit}
                className="relative rounded-2xl border border-white/10 bg-[#0c0b14]/95 p-7 shadow-2xl shadow-violet-950/40 backdrop-blur-xl sm:p-8"
              >
                <div className="flex items-center gap-2.5">
                  <span className="flex size-9 items-center justify-center rounded-lg bg-gradient-to-br from-violet-500 to-purple-700 shadow-[0_0_18px_rgba(124,58,237,0.45)]">
                    <Sparkles className="size-4 text-white" />
                  </span>
                  <div>
                    <h3 className="text-sm font-semibold tracking-tight text-foreground">
                      Request early access
                    </h3>
                    <p className="font-mono text-[10px] text-muted-foreground">
                      invite batches ship weekly
                    </p>
                  </div>
                </div>

                <label className="mt-6 block">
                  <span className="text-xs font-medium uppercase tracking-[0.12em] text-muted-foreground">
                    Work email
                  </span>
                  <input
                    type="email"
                    required
                    value={email}
                    onChange={(event) => setEmail(event.target.value)}
                    placeholder="you@company.com"
                    className="mt-2 w-full rounded-lg border border-white/10 bg-white/[0.03] px-3.5 py-2.5 text-sm text-foreground placeholder:text-muted-foreground/60 focus:border-violet-400/50 focus:outline-none focus:ring-2 focus:ring-violet-500/20"
                  />
                </label>

                <label className="mt-4 block">
                  <span className="text-xs font-medium uppercase tracking-[0.12em] text-muted-foreground">
                    Team size
                  </span>
                  <select
                    defaultValue="1–10"
                    className="mt-2 w-full rounded-lg border border-white/10 bg-white/[0.03] px-3.5 py-2.5 text-sm text-foreground focus:border-violet-400/50 focus:outline-none focus:ring-2 focus:ring-violet-500/20"
                  >
                    <option>1–10</option>
                    <option>11–50</option>
                    <option>51–200</option>
                    <option>201–1,000</option>
                    <option>1,000+</option>
                  </select>
                </label>

                <button
                  type="submit"
                  className={cn(
                    "group mt-6 inline-flex w-full items-center justify-center gap-2 rounded-lg bg-violet-600 px-5 py-3 text-sm font-medium text-white",
                    "shadow-[0_0_32px_rgba(124,58,237,0.45)] transition-all hover:bg-violet-500 hover:shadow-[0_0_44px_rgba(124,58,237,0.65)]",
                  )}
                >
                  Get my invitation
                  <ArrowRight className="size-4 transition-transform group-hover:translate-x-0.5" />
                </button>

                <p className="mt-4 text-center font-mono text-[10px] uppercase tracking-[0.16em] text-muted-foreground/70">
                  No spam · No commitment · Unsubscribe anytime
                </p>
              </form>
            </div>
          </Reveal>
        </div>
      </div>
    </section>
  );
}
