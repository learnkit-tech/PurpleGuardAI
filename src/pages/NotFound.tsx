import { motion } from "framer-motion";
import { useEffect, useState } from "react";
import { Link, useLocation } from "react-router";
import { Button } from "@/components/ui/button";
import { Home, ShieldCheck } from "lucide-react";

/**
 * Unknown routes redirect into the app after a short countdown. A dead 404
 * is the worst outcome for a phone user who mistyped a path — everything
 * recoverable should land back on the landing page.
 */
export default function NotFound() {
  const location = useLocation();
  const [seconds, setSeconds] = useState(4);

  useEffect(() => {
    const tick = setInterval(() => setSeconds((s) => s - 1), 1000);
    return () => clearInterval(tick);
  }, []);

  useEffect(() => {
    if (seconds <= 0) {
      window.location.href = "/";
    }
  }, [seconds]);

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.4 }}
      className="flex min-h-screen flex-col bg-background text-foreground"
    >
      <div className="flex flex-1 flex-col items-center justify-center px-4">
        <div className="w-full max-w-md text-center">
          <span className="mx-auto flex size-14 items-center justify-center rounded-2xl border border-violet-400/25 bg-violet-500/10 shadow-[0_0_30px_rgba(124,58,237,0.35)]">
            <ShieldCheck className="size-6 text-violet-300" />
          </span>
          <h1 className="mt-5 font-mono text-5xl font-bold tracking-tight text-foreground">
            404
          </h1>
          <p className="mt-2 text-lg text-foreground/85">Page not found</p>
          <p className="mt-3 break-all rounded-lg border border-white/[0.06] bg-white/[0.02] px-3 py-2 font-mono text-[11px] text-muted-foreground">
            {location.pathname}
          </p>
          <p className="mt-4 text-sm text-muted-foreground">
            Taking you to the landing page in{" "}
            <span className="font-mono text-violet-300">{Math.max(seconds, 0)}s</span>
            …
          </p>
          <div className="mt-6 flex flex-wrap items-center justify-center gap-2.5">
            <Button asChild className="bg-violet-600 text-white hover:bg-violet-500">
              <Link to="/">
                <Home className="size-4" />
                Go now
              </Link>
            </Button>
            <Button asChild variant="outline">
              <Link to="/dashboard">Open Console</Link>
            </Button>
          </div>
          <p className="mt-6 font-mono text-[10px] leading-relaxed text-muted-foreground/70">
            tip: open the bare origin (https://…vly.sh) or /dashboard — a
            missing https:// makes mobile browsers search instead of navigate
          </p>
        </div>
      </div>
    </motion.div>
  );
}
