import { useQuery } from "@tanstack/react-query"
import { createFileRoute } from "@tanstack/react-router"

import { listProjects } from "@/api/projects"
import { PageFailure, PageReading, ProjectsList } from "@/components/projects/projects-list"

export const Route = createFileRoute("/projects/")({
  component: ProjectsRoute,
})

function ProjectsRoute() {
  const query = useQuery({ queryKey: ["projects"], queryFn: () => listProjects() })
  if (query.isPending) return <PageReading what="the projects" />
  if (query.isError) return <PageFailure what="the projects" error={query.error} onRetry={() => void query.refetch()} />
  return <ProjectsList projects={query.data} />
}
