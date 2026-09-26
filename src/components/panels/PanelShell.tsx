import { ChevronDown, FolderGit2, LogOut, ShieldCheck, X } from "lucide-react";
import { PhoneQrButton } from "@/components/PhoneQrButton";
import type { ReactNode } from "react";
import { Link, useNavigate } from "react-router";
import { useQuery } from "convex/react";
import { api } from "@/convex/_generated/api";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useAuth } from "@/hooks/use-auth";
import { useProjectSelection } from "@/hooks/useProjectSelection";
import { cn } from "@/lib/utils";

export type PanelId = "console" | "hacker" | "developer" | "ecc";

const PANELS: Array<{ id: PanelId; label: string; href: string }> = [
  { id: "console", label: "Console", href: "/dashboard" },
  { id: "hacker", label: "Hacker", href: "/hacker" },
  { id: "developer", label: "Developer", href: "/developer" },
  { id: "ecc", label: "ECC", href: "/ecc" },
];

/**
 * Shared authenticated shell for all four PurpleGuard surfaces. Renders the
 * brand, the panel switcher, the shared project selector, and the account
 * menu so every panel operates on the same target.
 */
export function PanelShell({
  panel,
  badge,
  children,
}: {
  panel: PanelId;
  badge?: string;
  children: ReactNode;
}) {
  const { user, signOut } = useAuth();
  const navigate = useNavigate();
  const projectRows = useQuery(api.projects.list) ?? [];
  const { projectId, setProjectId } = useProjectSelection();
  const selected = projectRows.find((p) => p.repo === projectId);

  const handleSignOut = async () => {
    await signOut();
    navigate("/");
  };

  const initials = (user?.name || user?.email || "PG")
    .split(/[\s@]/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase())
    .join("");

  return (
    <div className="flex min-h-screen flex-col bg-background text-foreground">
      <header className="sticky top-0 z-40 border-b border-white/[0.06] bg-background/80 backdrop-blur-xl">
        <div className="flex h-16 items-center justify-between gap-4 px-4 sm:px-6">
          <div className="flex min-w-0 items-center gap-2.5">
            <Link
              to="/dashboard"
              className="flex shrink-0 items-center gap-2.5"
              aria-label="PurpleGuard AI"
            >
              <span className="flex size-8 items-center justify-center rounded-lg bg-gradient-to-br from-violet-500 to-purple-700 shadow-[0_0_20px_rgba(124,58,237,0.45)]">
                <ShieldCheck className="size-4 text-white" />
              </span>
              <span className="hidden text-[15px] font-semibold tracking-tight text-white sm:inline">
                PurpleGuard
                <span className="ml-1 bg-gradient-to-r from-violet-300 to-violet-500 bg-clip-text text-transparent">
                  AI
                </span>
              </span>
            </Link>
            {badge && (
              <span className="hidden rounded-full border border-violet-400/25 bg-violet-500/10 px-2.5 py-1 font-mono text-[10px] uppercase tracking-wider text-violet-200 md:inline-flex">
                {badge}
              </span>
            )}

            {/* Panel switcher */}
            <nav
              aria-label="PurpleGuard panels"
              className="ml-2 flex items-center gap-1 overflow-x-auto"
            >
              {PANELS.map((p) => (
                <Link
                  key={p.id}
                  to={p.href}
                  className={cn(
                    "shrink-0 rounded-md px-2.5 py-1.5 text-sm font-medium transition-colors",
                    p.id === panel
                      ? "bg-white/[0.07] text-foreground"
                      : "text-muted-foreground hover:bg-white/[0.04] hover:text-foreground",
                  )}
                >
                  {p.label}
                </Link>
              ))}
            </nav>

            {/* Shared project selector — every panel targets the same project */}
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <button
                  type="button"
                  className="ml-1 hidden max-w-[180px] items-center gap-1.5 rounded-md border border-white/10 bg-white/[0.03] px-2.5 py-1.5 text-xs text-muted-foreground transition-colors hover:text-foreground md:inline-flex"
                >
                  <FolderGit2 className="size-3.5 shrink-0 text-violet-300" />
                  <span className="truncate">
                    {selected ? selected.repo : "All projects"}
                  </span>
                  <ChevronDown className="size-3 shrink-0" />
                </button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="start" className="w-56">
                <DropdownMenuLabel className="font-mono text-[10px] uppercase tracking-[0.14em]">
                  Target project
                </DropdownMenuLabel>
                <DropdownMenuItem
                  onClick={() => setProjectId(null)}
                  className={cn("cursor-pointer", !projectId && "text-violet-200")}
                >
                  All projects
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                {projectRows.map((p) => (
                  <DropdownMenuItem
                    key={p.repo}
                    onClick={() => setProjectId(p.repo)}
                    className={cn("cursor-pointer", projectId === p.repo && "text-violet-200")}
                  >
                    <FolderGit2 className="mr-2 size-3.5 text-muted-foreground" />
                    <span className="truncate">{p.repo}</span>
                  </DropdownMenuItem>
                ))}
                {projectRows.length === 0 && (
                  <DropdownMenuItem disabled className="text-muted-foreground">
                    No projects yet — connect one in the Console
                  </DropdownMenuItem>
                )}
              </DropdownMenuContent>
            </DropdownMenu>
          </div>

          <div className="flex shrink-0 items-center gap-3">
            <PhoneQrButton />
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <button
                  type="button"
                  aria-label="Account menu"
                  className="flex size-8 items-center justify-center rounded-full bg-gradient-to-br from-violet-500 to-purple-700 font-mono text-xs font-semibold text-white shadow-[0_0_16px_rgba(124,58,237,0.4)] transition-transform hover:scale-105"
                >
                  {initials}
                </button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-56">
                <DropdownMenuLabel>
                  <p className="truncate text-sm font-medium text-foreground">
                    {user?.name || "Early access member"}
                  </p>
                  <p className="truncate text-xs font-normal text-muted-foreground">
                    {user?.email || "autonomous defender"}
                  </p>
                </DropdownMenuLabel>
                <DropdownMenuSeparator />
                <DropdownMenuItem
                  onClick={handleSignOut}
                  className="cursor-pointer text-destructive focus:text-destructive"
                >
                  <LogOut className="mr-2 size-4" />
                  Sign out
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </div>
      </header>
      <main className="min-w-0 flex-1">{children}</main>
    </div>
  );
}

/** Close button used by panel sub-views to return to a parent surface. */
export function PanelClose({ to }: { to: string }) {
  const navigate = useNavigate();
  return (
    <button
      type="button"
      onClick={() => navigate(to)}
      aria-label="Close"
      className="rounded-md p-1.5 text-muted-foreground transition-colors hover:bg-white/[0.04] hover:text-foreground"
    >
      <X className="size-4" />
    </button>
  );
}
