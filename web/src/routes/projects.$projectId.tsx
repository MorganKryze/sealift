import { useQuery } from "@tanstack/react-query"
import { createFileRoute } from "@tanstack/react-router"

import { getProject } from "@/api/projects"
import { ProjectPage } from "@/components/projects/project-page"
import { PageFailure, PageReading } from "@/components/projects/projects-list"

export const Route = createFileRoute("/projects/$projectId")({
  component: ProjectRoute,
})

function ProjectRoute() {
  const { projectId } = Route.useParams()
  // The same cache entry as the breadcrumb's and a session's, so the page costs one request.
  const query = useQuery({ queryKey: ["project", projectId], queryFn: () => getProject(projectId) })
  if (query.isPending) return <PageReading what="this project" />
  if (query.isError) return <PageFailure what="this project" error={query.error} onRetry={() => void query.refetch()} />
  return <ProjectPage key={projectId} project={query.data} />
}
