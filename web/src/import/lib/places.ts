import { HardDriveDownload, House, ServerCog } from "lucide-react"

import type { Crumb, Place } from "@/components/frame/frame"

// The frame draws the initials for both roles and the app build cannot reach this folder, so the definition lives there.
export { initials } from "@/components/frame/frame"

export const OFFLINE_PLACES: Place[] = [
  { to: "/", label: "Home", icon: House },
  { to: "/imports", label: "Imports", icon: HardDriveDownload },
]

export const OFFLINE_INSTANCE: Place = { to: "/instance", label: "Instance", icon: ServerCog }

/** The breadcrumb for a path of the import side: an import's page sits under Imports. */
export function offlineCrumbs(pathname: string): Crumb[] {
  if (pathname === "/instance") return [{ label: OFFLINE_INSTANCE.label }]
  if (pathname.startsWith("/imports/")) return [{ label: "Imports", to: "/imports" }, { label: "Import" }]
  if (pathname === "/imports") return [{ label: "Imports" }]
  return [{ label: "Home" }]
}
