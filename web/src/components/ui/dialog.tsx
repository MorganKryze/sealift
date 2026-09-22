import * as DialogPrimitive from "@radix-ui/react-dialog"
import type { ComponentProps } from "react"

import { cn } from "@/lib/utils"

const Dialog = DialogPrimitive.Root
const DialogTrigger = DialogPrimitive.Trigger

function DialogContent({ className, children, ...props }: ComponentProps<typeof DialogPrimitive.Content>) {
  return (
    <DialogPrimitive.Portal>
      <DialogPrimitive.Overlay className="animate-fade fixed inset-0 z-40 grid place-items-center bg-ink/45 p-4">
        <DialogPrimitive.Content
          className={cn(
            "animate-enter w-full max-w-[460px] rounded-xl border border-line bg-background p-6 shadow-lg",
            className,
          )}
          {...props}
        >
          {children}
        </DialogPrimitive.Content>
      </DialogPrimitive.Overlay>
    </DialogPrimitive.Portal>
  )
}

function DialogTitle(props: ComponentProps<typeof DialogPrimitive.Title>) {
  return <DialogPrimitive.Title className="text-lg font-semibold text-ink" {...props} />
}

function DialogDescription(props: ComponentProps<typeof DialogPrimitive.Description>) {
  return <DialogPrimitive.Description className="mt-2 text-sm text-muted" {...props} />
}

function DialogFooter({ className, ...props }: ComponentProps<"div">) {
  return <div className={cn("mt-5 flex justify-end gap-3", className)} {...props} />
}

export { Dialog, DialogContent, DialogDescription, DialogFooter, DialogTitle, DialogTrigger }
