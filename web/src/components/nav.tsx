import { Link } from "@tanstack/react-router"
import { Settings } from "lucide-react"

import { Lockup } from "@/components/brand/Lockup"
import { ThemeToggle } from "@/components/theme-toggle"

/**
 * The topbar: sealift is a single guided flow, not a multi-page app, so
 * navigation is just home (the brand) and settings, not a section list.
 */
export function Nav() {
  return (
    <header className="sticky top-0 z-20 border-b border-line bg-background/90 backdrop-blur">
      <div className="mx-auto flex h-15 max-w-240 items-center gap-4 px-5">
        <Link to="/" aria-label="sealift home" className="flex items-center gap-2 outline-none focus-visible:ring-2 focus-visible:ring-accent">
          <Lockup size={22} />
        </Link>
        <span className="flex-1" />
        <ThemeToggle />
        <Link
          to="/settings"
          className="flex h-8.5 items-center gap-1.5 rounded-md px-2.5 text-sm text-muted outline-none hover:bg-card hover:text-ink focus-visible:ring-2 focus-visible:ring-accent [&.active]:text-ink"
          activeProps={{ className: "active" }}
        >
          <Settings className="size-4" />
          Settings
        </Link>
      </div>
    </header>
  )
}
