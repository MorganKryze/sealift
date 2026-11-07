import { Link } from "@tanstack/react-router"
import { Settings } from "lucide-react"
import { useState } from "react"

import { Lockup } from "@/components/brand/Lockup"
import { cn } from "@/lib/utils"
import { useMe } from "@/import/api/queries"

import { SettingsSheet } from "./settings-sheet"

const linkClass =
  "flex h-8 items-center rounded-md px-2.5 text-sm text-muted outline-none hover:bg-card hover:text-ink focus-visible:ring-2 focus-visible:ring-accent"
const currentClass = "bg-card font-medium text-ink"

/** The topbar of every import screen. */
export function ImportHeader() {
  const [sheetOpen, setSheetOpen] = useState(false)
  const me = useMe()

  return (
    <header className="sticky top-0 z-20 border-b border-line bg-background/90 backdrop-blur">
      <div className="mx-auto flex h-15 max-w-240 items-center gap-4 px-5">
        <Lockup size={22} />
        <nav aria-label="Import" className="ml-4 flex items-center gap-1">
          <Link to="/" activeOptions={{ exact: true }} className={linkClass} activeProps={{ className: cn(linkClass, currentClass) }}>
            Archives
          </Link>
          <Link to="/imports" className={linkClass} activeProps={{ className: cn(linkClass, currentClass) }}>
            Imports
          </Link>
        </nav>
        <span className="flex-1" />
        <span className="max-w-48 truncate text-sm text-muted" title={me.data?.user}>
          {me.isPending ? "Loading user" : (me.data?.user ?? "User not read")}
        </span>
        <button
          type="button"
          onClick={() => setSheetOpen(true)}
          className="flex h-8 items-center gap-1.5 rounded-md px-2.5 text-sm text-muted outline-none hover:bg-card hover:text-ink focus-visible:ring-2 focus-visible:ring-accent"
        >
          <Settings className="size-4" />
          Settings
        </button>
      </div>
      <SettingsSheet open={sheetOpen} onClose={() => setSheetOpen(false)} />
    </header>
  )
}
