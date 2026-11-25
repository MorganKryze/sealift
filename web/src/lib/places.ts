import { FolderGit2, House, ServerCog } from "lucide-react"

import type { Project } from "@/api/projects"
import type { Crumb, Place } from "@/components/frame/frame"
import { crossingName } from "@/lib/crossings"
import { latestByDate } from "@/lib/utils"

export const ONLINE_PLACES: Place[] = [
  { to: "/", label: "Home", icon: House },
  { to: "/projects", label: "Projects", icon: FolderGit2 },
]

export const ONLINE_INSTANCE: Place = { to: "/instance", label: "Instance", icon: ServerCog }

/**
 * The breadcrumb for a path of the connected side. Once the project has loaded, its page reads the
 * project's name and a session reads its crossing's name; a plain string is taken as the name.
 */
export function onlineCrumbs(pathname: string, project?: string | Pick<Project, "name" | "analyses">): Crumb[] {
  const name = typeof project === "string" ? project : project?.name
  if (pathname === "/instance") return [{ label: ONLINE_INSTANCE.label }]
  if (pathname === "/update") return [{ label: "Home", to: "/" }, { label: "Update" }]
  if (pathname === "/projects") return [{ label: "Projects" }]
  if (pathname.startsWith("/projects/")) return [{ label: "Projects", to: "/projects" }, { label: name ?? "Project" }]
  if (pathname.startsWith("/sessions/")) {
    const analyses = typeof project === "object" ? (project.analyses ?? []) : []
    const latest = latestByDate(analyses)
    return [{ label: "Home", to: "/" }, { label: latest && name ? crossingName(name, latest, analyses) : (name ?? "Crossing") }]
  }
  return [{ label: "Home" }]
}
