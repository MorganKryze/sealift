import { useQuery, useQueryClient } from "@tanstack/react-query"
import { createFileRoute, Navigate, useNavigate } from "@tanstack/react-router"

import { getProject } from "@/api/projects"
import { ExportScreen } from "@/components/session/export-screen"
import type { StepId } from "@/components/step-bar"
import { isJobActive, JOB_POLL_INTERVAL_MS, latestByDate } from "@/lib/utils"

export const Route = createFileRoute("/sessions/$sessionId/export")({
  component: ExportRoute,
})

function ExportRoute() {
  const { sessionId } = Route.useParams()
  const navigate = useNavigate()
  const queryClient = useQueryClient()

  const query = useQuery({
    queryKey: ["project", sessionId],
    queryFn: () => getProject(sessionId),
    refetchInterval: (q) => {
      const project = q.state.data
      const analysis = latestByDate(project?.analyses)
      const relatedExport = analysis
        ? latestByDate(project?.exports?.filter((candidate) => candidate.analysisId === analysis.id))
        : undefined
      return isJobActive(relatedExport) ? JOB_POLL_INTERVAL_MS : false
    },
  })

  if (query.isPending) {
    return (
      <div role="status" className="flex flex-1 items-center justify-center p-8 text-muted">
        Loading session…
      </div>
    )
  }

  if (query.isError) {
    return (
      <p role="alert" className="p-8 text-sm text-severity-critical-fg">
        Could not load this session.
      </p>
    )
  }

  const project = query.data
  const analysis = latestByDate(project.analyses)

  if (!analysis || analysis.state !== "done") {
    return <Navigate to="/sessions/$sessionId/analysis" params={{ sessionId }} replace />
  }

  const relatedExport = latestByDate(project.exports?.filter((candidate) => candidate.analysisId === analysis.id))

  function goToStep(step: StepId) {
    switch (step) {
      case "drop":
        void navigate({ to: "/sessions/$sessionId/drop", params: { sessionId } })
        break
      case "analysis":
        void navigate({ to: "/sessions/$sessionId/analysis", params: { sessionId } })
        break
      case "review":
        void navigate({ to: "/sessions/$sessionId/review", params: { sessionId } })
        break
      case "export":
        void navigate({ to: "/sessions/$sessionId/export", params: { sessionId } })
        break
    }
  }

  return (
    <ExportScreen
      project={project}
      analysis={analysis}
      relatedExport={relatedExport}
      onChanged={() => void queryClient.invalidateQueries({ queryKey: ["project", sessionId] })}
      onNavigateStep={goToStep}
    />
  )
}
