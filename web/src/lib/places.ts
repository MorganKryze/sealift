import { House, ServerCog } from "lucide-react"

import type { Crumb, Place } from "@/components/frame/frame"

export const ONLINE_PLACES: Place[] = [{ to: "/", label: "Home", icon: House }]

export const ONLINE_INSTANCE: Place = { to: "/settings", label: "Instance", icon: ServerCog }

/** The breadcrumb for a path of the connected side; a session reads its project's name once it has loaded. */
export function onlineCrumbs(pathname: string, projectName?: string): Crumb[] {
  if (pathname === "/settings") return [{ label: ONLINE_INSTANCE.label }]
  if (pathname.startsWith("/sessions/")) return [{ label: "Home", to: "/" }, { label: projectName ?? "Crossing" }]
  return [{ label: "Home" }]
}
