import * as DialogPrimitive from "@radix-ui/react-dialog"
import { useQuery } from "@tanstack/react-query"
import { X } from "lucide-react"
import { createContext, useContext, useState, type ReactNode } from "react"

import { getSettings } from "@/api/settings"
import { SettingsForm } from "@/components/settings/settings-form"
import { ToolsPanel } from "@/components/settings/tools-panel"
import { ThemeToggle } from "@/components/theme-toggle"
import { useReturnFocus } from "@/hooks/use-return-focus"

const SettingsPanelContext = createContext<{ open: () => void } | null>(null)

/** Opens the settings side panel from anywhere: the topbar, a failure's "Open settings", the /settings address. */
export function useSettingsPanel() {
  const context = useContext(SettingsPanelContext)
  if (!context) {
    throw new Error("useSettingsPanel needs a SettingsPanelProvider above it")
  }
  return context
}

export function SettingsPanelProvider({ children }: { children: ReactNode }) {
  const [isOpen, setIsOpen] = useState(false)
  const returnFocus = useReturnFocus()

  return (
    <SettingsPanelContext.Provider
      value={{
        open: () => {
          returnFocus.remember()
          setIsOpen(true)
        },
      }}
    >
      {children}
      <DialogPrimitive.Root open={isOpen} onOpenChange={setIsOpen}>
        <DialogPrimitive.Portal>
          <DialogPrimitive.Overlay className="animate-fade fixed inset-0 z-40 bg-black/50" />
          <DialogPrimitive.Content
            aria-describedby={undefined}
            onCloseAutoFocus={returnFocus.onCloseAutoFocus}
            // Focus the panel itself on open: Radix would focus the close button, which reads as the main action.
            onOpenAutoFocus={(event) => {
              event.preventDefault()
              ;(event.currentTarget as HTMLElement).focus()
            }}
            tabIndex={-1}
            className="animate-slide-in fixed top-0 right-0 bottom-0 z-50 flex w-[min(440px,100%)] flex-col overflow-y-auto border-l border-line bg-background shadow-xl outline-none"
          >
            <div className="sticky top-0 z-10 flex items-center justify-between border-b border-line bg-background/95 px-6 py-4 backdrop-blur">
              <DialogPrimitive.Title className="text-lg font-semibold text-ink">Settings</DialogPrimitive.Title>
              <DialogPrimitive.Close
                aria-label="Close settings"
                className="rounded-md p-1.5 text-muted outline-none hover:bg-card hover:text-ink focus-visible:ring-2 focus-visible:ring-accent"
              >
                <X className="size-4" />
              </DialogPrimitive.Close>
            </div>
            <SettingsPanelBody />
          </DialogPrimitive.Content>
        </DialogPrimitive.Portal>
      </DialogPrimitive.Root>
    </SettingsPanelContext.Provider>
  )
}

function SettingsPanelBody() {
  const settingsQuery = useQuery({ queryKey: ["settings"], queryFn: getSettings })

  return (
    <div className="flex flex-col gap-8 px-6 py-6">
      <section className="flex flex-col gap-4">
        <div>
          <h2 className="text-base font-semibold text-ink">Appearance</h2>
          <p className="mt-0.5 text-sm text-muted">Saved in this browser only.</p>
        </div>
        <ThemeToggle />
      </section>

      {settingsQuery.isPending ? (
        <p role="status" className="text-sm text-muted">
          Loading settings…
        </p>
      ) : settingsQuery.isError ? (
        <p role="alert" className="text-sm text-severity-critical-fg">
          Could not load the settings: {settingsQuery.error.message}
        </p>
      ) : (
        <>
          <SettingsForm settings={settingsQuery.data} />
          <ToolsPanel minReleaseAgeDays={settingsQuery.data.minReleaseAgeDays} pnpmVersion={settingsQuery.data.target.pnpmVer} />
        </>
      )}
    </div>
  )
}
