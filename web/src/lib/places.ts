import { FolderGit2, House, ServerCog } from "lucide-react"

import type { Project } from "@/api/projects"
import type { Crumb, Place } from "@/components/frame/frame"
import { crossingName } from "@/lib/crossings"
import { shownAnalysis } from "@/lib/session-analysis"

export const ONLINE_PLACES: Place[] = [
  { to: "/", label: "Home", icon: House },
  { to: "/projects", label: "Projects", icon: FolderGit2 },
]

export const ONLINE_INSTANCE: Place = { to: "/instance", label: "Instance", icon: ServerCog }

/**
 * The breadcrumb for a path of the connected side. Once the project has loaded, its page reads the
 * project's name and a crossing reads the name of the crossing its link opens, else the latest one;
 * a plain string is taken as the name.
 */
export function onlineCrumbs(pathname: string, project?: string | Pick<Project, "name" | "analyses">, analysisId?: string): Crumb[] {
  const name = typeof project === "string" ? project : project?.name
  if (pathname === "/instance") return [{ label: ONLINE_INSTANCE.label }]
  if (pathname === "/update") return [{ label: "Home", to: "/" }, { label: "Update" }]
  if (pathname === "/projects") return [{ label: "Projects" }]
  if (pathname.startsWith("/projects/")) return [{ label: "Projects", to: "/projects" }, { label: name ?? "Project" }]
  if (pathname.startsWith("/crossings/")) {
    const analyses = typeof project === "object" ? (project.analyses ?? []) : []
    const shown = shownAnalysis(analyses, analysisId)
    return [{ label: "Home", to: "/" }, { label: shown && name ? crossingName(name, shown, analyses) : (name ?? "Crossing") }]
  }
  return [{ label: "Home" }]
}
