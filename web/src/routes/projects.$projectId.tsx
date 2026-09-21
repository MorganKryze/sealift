import { useQueryClient } from "@tanstack/react-query"
import { createFileRoute } from "@tanstack/react-router"

import type { Project } from "@/api/projects"

export const Route = createFileRoute("/projects/$projectId")({
  component: ProjectPlaceholder,
})

// Placeholder until the analysis screen lands: reads the project the create
// mutation cached on upload, so a fresh navigation shows its name right away.
function ProjectPlaceholder() {
  const { projectId } = Route.useParams()
  const queryClient = useQueryClient()
  const project = queryClient.getQueryData<Project>(["project", projectId])

  return (
    <div className="flex flex-1 flex-col items-center justify-center gap-2 p-8 text-center">
      <h1 className="text-xl font-semibold text-ink">{project?.name ?? "Project"}</h1>
      <p className="text-muted">Analysis queued</p>
    </div>
  )
}
