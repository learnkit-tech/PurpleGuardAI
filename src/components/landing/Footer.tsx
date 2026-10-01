import { Github, Linkedin, ShieldCheck, Twitter } from "lucide-react";
import { FOOTER_COLUMNS } from "./data";

const SOCIALS = [
  { label: "LinkedIn", href: "#contact", icon: Linkedin },
  { label: "X", href: "#contact", icon: Twitter },
  { label: "GitHub", href: "#contact", icon: Github },
];

export function Footer() {
  const year = new Date().getFullYear();

  return (
    <footer className="border-t border-white/[0.06]">
      <div className="mx-auto max-w-7xl px-4 py-16 sm:px-6 lg:px-8">
        <div className="grid gap-12 lg:grid-cols-[1.4fr_2fr]">
          {/* Brand */}
          <div className="max-w-sm">
            <a href="#top" className="flex items-center gap-2.5" aria-label="PurpleGuard AI home">
              <span className="flex size-8 items-center justify-center rounded-lg bg-gradient-to-br from-violet-500 to-purple-700 shadow-[0_0_20px_rgba(124,58,237,0.4)]">
                <ShieldCheck className="size-4 text-white" />
              </span>
              <span className="text-[15px] font-semibold tracking-tight text-white">
                PurpleGuard
                <span className="ml-1 bg-gradient-to-r from-violet-300 to-violet-500 bg-clip-text text-transparent">
                  AI
                </span>
              </span>
            </a>
            <p className="mt-4 text-sm leading-relaxed text-muted-foreground">
              Autonomous cybersecurity, powered by ECC — the intelligence layer
              that detects, reasons, and remediates before attackers can act.
            </p>
            <div className="mt-6 flex items-center gap-2">
              {SOCIALS.map((social) => (
                <a
                  key={social.label}
                  href={social.href}
                  aria-label={social.label}
                  className="flex size-9 items-center justify-center rounded-lg border border-white/10 bg-white/[0.02] text-muted-foreground transition-all hover:border-violet-400/40 hover:bg-violet-500/10 hover:text-violet-200"
                >
                  <social.icon className="size-4" />
                </a>
              ))}
            </div>
          </div>

          {/* Link columns */}
          <div className="grid grid-cols-2 gap-8 sm:grid-cols-3">
            {FOOTER_COLUMNS.map((column) => (
              <nav key={column.heading} aria-label={column.heading}>
                <h3 className="font-mono text-[11px] font-medium uppercase tracking-[0.18em] text-muted-foreground">
                  {column.heading}
                </h3>
                <ul className="mt-4 space-y-2.5">
                  {column.links.map((link) => (
                    <li key={link.label}>
                      <a
                        href={link.href}
                        className="text-sm text-muted-foreground transition-colors hover:text-foreground"
                      >
                        {link.label}
                      </a>
                    </li>
                  ))}
                </ul>
              </nav>
            ))}
          </div>
        </div>

        {/* Bottom bar */}
        <div className="mt-14 flex flex-col items-center justify-between gap-4 border-t border-white/[0.06] pt-7 sm:flex-row">
          <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted-foreground">
            Copyright © {year} PurpleGuard AI
          </p>
          <div className="flex items-center gap-6">
            <a
              href="#contact"
              className="text-xs text-muted-foreground transition-colors hover:text-foreground"
            >
              Privacy
            </a>
            <a
              href="#contact"
              className="text-xs text-muted-foreground transition-colors hover:text-foreground"
            >
              Terms
            </a>
            <a
              href="#contact"
              className="text-xs text-muted-foreground transition-colors hover:text-foreground"
            >
              Status
            </a>
          </div>
        </div>
      </div>
    </footer>
  );
}
