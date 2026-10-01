import { Check, X } from "lucide-react";
import { Reveal } from "./Reveal";
import { SectionHeader } from "./SectionHeader";
import { COMPARISON_ROWS } from "./data";

export function Comparison() {
  return (
    <section id="compare" className="relative py-24 sm:py-32">
      <div className="mx-auto max-w-6xl px-4 sm:px-6 lg:px-8">
        <SectionHeader
          eyebrow="Why PurpleGuard AI"
          title="Traditional tools detect. PurpleGuard reasons, fixes, and learns."
          description="The gap between alerting and acting is where breaches happen. PurpleGuard AI + ECC closes it — autonomously, explainably, and safely."
        />

        <Reveal delay={0.1} className="mt-14">
          <div className="overflow-hidden rounded-2xl border border-white/[0.08]">
            <div className="overflow-x-auto">
              <table className="w-full min-w-[680px] border-collapse text-left">
                <thead>
                  <tr className="border-b border-white/[0.08] bg-white/[0.02]">
                    <th
                      scope="col"
                      className="w-[26%] px-5 py-4 text-xs font-medium uppercase tracking-[0.14em] text-muted-foreground"
                    >
                      Capability
                    </th>
                    <th
                      scope="col"
                      className="px-5 py-4 text-sm font-medium text-muted-foreground"
                    >
                      Traditional Security Tools
                    </th>
                    <th
                      scope="col"
                      className="bg-violet-500/[0.08] px-5 py-4 text-sm font-semibold text-violet-200"
                    >
                      PurpleGuard AI + ECC
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {COMPARISON_ROWS.map((row) => (
                    <tr
                      key={row.label}
                      className="border-b border-white/[0.05] transition-colors last:border-b-0 hover:bg-white/[0.02]"
                    >
                      <th
                        scope="row"
                        className="px-5 py-4 text-sm font-medium text-foreground"
                      >
                        {row.label}
                      </th>
                      <td className="px-5 py-4">
                        <span className="flex items-start gap-2.5 text-sm text-muted-foreground">
                          <span className="mt-0.5 flex size-4 shrink-0 items-center justify-center rounded-full border border-white/10 bg-white/[0.03]">
                            <X className="size-2.5 text-white/40" />
                          </span>
                          {row.traditional}
                        </span>
                      </td>
                      <td className="bg-violet-500/[0.06] px-5 py-4">
                        <span className="flex items-start gap-2.5 text-sm text-foreground/90">
                          <span className="mt-0.5 flex size-4 shrink-0 items-center justify-center rounded-full bg-violet-500/25">
                            <Check className="size-2.5 text-violet-200" />
                          </span>
                          {row.purpleguard}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="border-t border-white/[0.06] bg-white/[0.02] px-5 py-3.5 font-mono text-[11px] uppercase tracking-[0.16em] text-muted-foreground">
              Autonomous where you want it — human-approved where you need it.
            </p>
          </div>
        </Reveal>
      </div>
    </section>
  );
}
