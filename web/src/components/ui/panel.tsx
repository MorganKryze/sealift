import * as DialogPrimitive from "@radix-ui/react-dialog"
import { X, type LucideIcon } from "lucide-react"
import { useRef, type ReactNode } from "react"

import { cn } from "@/lib/utils"

interface PanelProps {
  open: boolean
  onClose: () => void
  /** The header band's state colour: warn for a decision, info for a jump, bad for a refusal. */
  tone: "warn" | "info" | "bad"
  heading: string
  icon: LucideIcon
  children: ReactNode
  /** What takes the focus back once the panel closes, when it is still on the page. */
  returnFocus?: HTMLElement | null
}

const TONES = {
  warn: "border-warn-line bg-warn-tint text-warn",
  info: "border-info-line bg-info-tint text-info",
  // A refusal is the loudest panel: the band is filled.
  bad: "border-bad bg-bad text-bg",
}

/**
 * A decision on one item, 480 px from the right over a scrim. The focus stays inside while it is open and
 * goes back on close; Escape and the scrim close it with nothing recorded. An info popover open inside it
 * takes the Escape first.
 */
export function Panel({ open, onClose, tone, heading, icon: Icon, children, returnFocus }: PanelProps) {
  const content = useRef<HTMLDivElement>(null)
  const opener = useRef<HTMLElement | null>(null)
  return (
    <DialogPrimitive.Root open={open} onOpenChange={(next) => (next ? undefined : onClose())}>
      <DialogPrimitive.Portal>
        <DialogPrimitive.Overlay className="animate-fade fixed inset-0 z-40 bg-black/40" />
        <DialogPrimitive.Content
          ref={content}
          aria-describedby={undefined}
          onEscapeKeyDown={(event) => {
            if (content.current?.querySelector("[data-term-open]")) event.preventDefault()
          }}
          onOpenAutoFocus={() => {
            opener.current = document.activeElement instanceof HTMLElement ? document.activeElement : null
          }}
          onCloseAutoFocus={(event) => {
            // The dialog primitive gives the focus to its trigger, and a panel opened from a row has none:
            // the focus goes to returnFocus, else back to what held it when the panel opened.
            event.preventDefault()
            const target = returnFocus ?? opener.current
            if (target?.isConnected) target.focus()
          }}
          className={cn(
            "fixed inset-y-0 right-0 z-50 flex w-full max-w-[480px] flex-col bg-bg shadow-[-12px_0_32px_rgba(var(--shadow),0.18)] outline-none",
            "transition-transform duration-300 ease-[var(--ease-out)] starting:translate-x-full motion-reduce:transition-none",
          )}
        >
          <div className={cn("flex min-h-19 flex-none items-center gap-3 border-b px-6", TONES[tone])}>
            <Icon aria-hidden="true" className="size-7 flex-none" />
            <DialogPrimitive.Title className="flex-1 text-[28px] leading-tight font-semibold tracking-tight">{heading}</DialogPrimitive.Title>
            <DialogPrimitive.Close
              aria-label="Close"
              className="grid size-8 flex-none place-items-center rounded-lg transition-colors duration-150 [@media(hover:hover)_and_(pointer:fine)]:hover:bg-bg/60"
            >
              <X aria-hidden="true" className="size-4" />
            </DialogPrimitive.Close>
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto px-6 py-6">{children}</div>
        </DialogPrimitive.Content>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  )
}
