import { Link } from "@tanstack/react-router"
import { Settings } from "lucide-react"

import { Lockup } from "@/components/brand/Lockup"
import { useSettingsPanel } from "@/components/settings/settings-panel"

/**
 * The topbar: sealift is a single guided flow, not a multi-page app, so
 * navigation is just home (the brand) and settings, not a section list.
 */
export function Nav() {
  const settingsPanel = useSettingsPanel()

  return (
    <header className="sticky top-0 z-20 border-b border-line bg-background/90 backdrop-blur">
      <div className="mx-auto flex h-15 max-w-240 items-center gap-4 px-5">
        <Link to="/" aria-label="sealift home" className="flex items-center gap-2 outline-none focus-visible:ring-2 focus-visible:ring-accent">
          <Lockup size={22} />
        </Link>
        <span className="flex-1" />
        <button
          type="button"
          onClick={settingsPanel.open}
          className="flex h-8.5 items-center gap-1.5 rounded-md px-2.5 text-sm text-muted outline-none hover:bg-card hover:text-ink focus-visible:ring-2 focus-visible:ring-accent"
        >
          <Settings className="size-4" />
          Settings
        </button>
      </div>
    </header>
  )
}
