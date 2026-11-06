import { X } from "lucide-react"
import { useEffect, useRef } from "react"

import { ThemeToggle } from "@/components/theme-toggle"
import { useReturnFocus } from "@/hooks/use-return-focus"
import { useMe } from "@/import/api/queries"

interface SettingsSheetProps {
  open: boolean
  onClose: () => void
}

/**
 * A native dialog: Radix's scroll lock injects a style element, which the
 * screens' policy (style-src 'self') blocks.
 */
export function SettingsSheet({ open, onClose }: SettingsSheetProps) {
  const dialog = useRef<HTMLDialogElement>(null)
  const returnFocus = useReturnFocus()
  const wasOpen = useRef(false)
  const me = useMe()

  useEffect(() => {
    const element = dialog.current
    if (!element) {
      return
    }
    if (open && !element.open) {
      returnFocus.remember()
      element.showModal()
      element.focus()
    } else if (!open && element.open) {
      element.close()
    }
    if (!open && wasOpen.current) {
      returnFocus.onCloseAutoFocus(new Event("close"))
    }
    wasOpen.current = open
    // The hook's functions read a ref only; listing them would rerun the effect on every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open])

  const value = (read: string | undefined) => (me.isPending ? "Loading" : (read ?? "Not read"))

  return (
    <dialog
      ref={dialog}
      aria-labelledby="import-settings-title"
      tabIndex={-1}
      onCancel={(event) => {
        event.preventDefault()
        onClose()
      }}
      onKeyDown={(event) => {
        if (event.key === "Escape") {
          event.preventDefault()
          onClose()
        }
      }}
      onClick={(event) => {
        if (event.target === dialog.current) {
          onClose()
        }
      }}
      className="fixed top-0 right-0 bottom-0 left-auto m-0 h-full max-h-none w-[min(440px,100%)] max-w-none border-l border-line bg-background p-0 text-ink shadow-xl outline-none backdrop:bg-black/50"
    >
      <div className="flex items-center justify-between border-b border-line px-6 py-4">
        <h2 id="import-settings-title" className="text-lg font-semibold text-ink">
          Settings
        </h2>
        <button
          type="button"
          aria-label="Close settings"
          onClick={onClose}
          className="flex size-8 items-center justify-center rounded-md text-muted outline-none hover:bg-card hover:text-ink focus-visible:ring-2 focus-visible:ring-accent"
        >
          <X className="size-4" />
        </button>
      </div>
      <div className="flex flex-col gap-8 px-6 py-6">
        <section className="flex flex-col gap-4">
          <div>
            <h3 className="text-base font-semibold text-ink">Appearance</h3>
            <p className="mt-0.5 text-sm text-muted">Saved in this browser only.</p>
          </div>
          <ThemeToggle />
        </section>
        <section className="flex flex-col gap-4">
          <div>
            <h3 className="text-base font-semibold text-ink">Your MinIO folder</h3>
            <p className="mt-0.5 text-sm text-muted">Archives are read from here. The administrator sets it from your user name.</p>
          </div>
          <dl className="grid gap-3 text-sm">
            <div>
              <dt className="text-muted">Bucket</dt>
              <dd className="mt-0.5 font-mono [overflow-wrap:anywhere]">{value(me.data?.bucket)}</dd>
            </div>
            <div>
              <dt className="text-muted">Folder</dt>
              <dd className="mt-0.5 font-mono [overflow-wrap:anywhere]">{value(me.data?.folder)}</dd>
            </div>
          </dl>
        </section>
      </div>
    </dialog>
  )
}
