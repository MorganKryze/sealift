import { useQuery, useQueryClient } from "@tanstack/react-query"
import { SessionLoadError } from "@/components/route-error"
import { createFileRoute, useNavigate } from "@tanstack/react-router"

import { getProject } from "@/api/projects"
import { AnalysisScreen } from "@/components/session/analysis-screen"
import type { StepId } from "@/components/step-bar"
import { isJobActive, JOB_POLL_INTERVAL_MS, latestByDate } from "@/lib/utils"

export const Route = createFileRoute("/sessions/$sessionId/analysis")({
  component: AnalysisRoute,
})

function AnalysisRoute() {
  const { sessionId } = Route.useParams()
  const queryClient = useQueryClient()
  const navigate = useNavigate()

  const query = useQuery({
    queryKey: ["project", sessionId],
    queryFn: () => getProject(sessionId),
    refetchInterval: (q) => (isJobActive(latestByDate(q.state.data?.analyses)) ? JOB_POLL_INTERVAL_MS : false),
  })

  if (query.isPending) {
    return (
      <div role="status" className="flex flex-1 items-center justify-center p-8 text-muted">
        Loading session…
      </div>
    )
  }

  if (query.isError) {
    return <SessionLoadError error={query.error} onRetry={() => void query.refetch()} />
  }

  const analysis = latestByDate(query.data.analyses)
  if (!analysis) {
    return <p className="p-8 text-muted">No analysis yet.</p>
  }

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
    <AnalysisScreen
      // Retry queues a new analysis with a new id under the same route: a
      // fresh key here remounts the screen (and useJobEvents inside it)
      // instead of reusing an instance still holding the previous run's
      // steps and progress.
      key={analysis.id}
      projectId={sessionId}
      project={query.data}
      analysis={analysis}
      onChanged={() => void queryClient.invalidateQueries({ queryKey: ["project", sessionId] })}
      onNavigateStep={goToStep}
    />
  )
}
