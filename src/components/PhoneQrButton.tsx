import { useState } from "react";
import { QRCodeSVG } from "qrcode.react";
import { Copy, ExternalLink, Smartphone } from "lucide-react";
import { toast } from "sonner";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

/**
 * "Open on your phone" — the primary action is a real tappable https:// link
 * (a pasted/tapped link always navigates; a typed bare domain often turns
 * into a search). QR stays as a secondary option for two-device setups.
 */
export function PhoneQrButton() {
  const [open, setOpen] = useState(false);
  const url = typeof window !== "undefined" ? window.location.origin : "";
  const isPublic = /\.(vly|freebuff)\.sh$|\.freebuff\.app$/.test(
    typeof window !== "undefined" ? window.location.hostname : "",
  );

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(url);
      toast.success("Link copied — paste it anywhere and tap it");
    } catch {
      toast.error("Copy failed — select and copy the URL text below");
    }
  };

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        aria-label="Get the phone link"
        title="Get the phone link"
        className="hidden size-8 items-center justify-center rounded-full border border-white/10 bg-white/[0.03] text-violet-300 transition-colors hover:bg-white/[0.08] sm:flex"
      >
        <Smartphone className="size-4" />
      </button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-w-sm border-white/10 bg-[oklch(0.16_0.012_288)]">
          <DialogHeader>
            <DialogTitle>Open on your phone</DialogTitle>
            <DialogDescription>
              Tap the button below on your phone, or copy the link and tap it
              from anywhere (notes, chat, email). It includes https:// so it
              always opens as a link — never a search.
            </DialogDescription>
          </DialogHeader>
          <div className="flex flex-col items-center gap-3 py-1">
            {isPublic ? (
              <a
                href={url}
                className="flex w-full items-center justify-center gap-2 rounded-xl bg-violet-600 px-4 py-3 text-sm font-medium text-white shadow-[0_0_24px_rgba(124,58,237,0.4)] transition-colors hover:bg-violet-500"
              >
                <ExternalLink className="size-4" />
                Open {url.replace(/^https?:\/\//, "")}
              </a>
            ) : (
              <p className="w-full rounded-lg border border-amber-400/25 bg-amber-400/10 p-3 text-center text-xs leading-relaxed text-amber-200">
                This preview is on {url} — a private address your phone can't
                reach. Open the preview from the Freebuff project page (a
                *.vly.sh URL) and get the link there.
              </p>
            )}
            <div className="flex w-full items-center gap-2">
              <code className="min-w-0 flex-1 truncate rounded-lg border border-white/10 bg-black/30 px-3 py-2 font-mono text-[11px] text-violet-200">
                {url}
              </code>
              <button
                type="button"
                onClick={() => void copy()}
                className="flex shrink-0 items-center gap-1.5 rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2 font-mono text-[10px] text-muted-foreground transition-colors hover:text-foreground"
              >
                <Copy className="size-3.5" />
                copy
              </button>
            </div>
            {isPublic && (
              <details className="w-full">
                <summary className="cursor-pointer text-center font-mono text-[10px] text-muted-foreground hover:text-foreground">
                  show QR (for a second device)
                </summary>
                <div className="mt-3 flex flex-col items-center gap-2">
                  <div className="rounded-xl bg-white p-3">
                    <QRCodeSVG value={url} size={150} />
                  </div>
                </div>
              </details>
            )}
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}
