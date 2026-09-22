import { useQuery, useQueryClient } from "@tanstack/react-query"
import { createFileRoute } from "@tanstack/react-router"

import { getProject } from "@/api/projects"
import { AnalysisScreen } from "@/components/session/analysis-screen"
import { isJobActive, JOB_POLL_INTERVAL_MS, latestByDate } from "@/lib/utils"

export const Route = createFileRoute("/sessions/$sessionId/analysis")({
  component: AnalysisRoute,
})

function AnalysisRoute() {
  const { sessionId } = Route.useParams()
  const queryClient = useQueryClient()

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
    return (
      <p role="alert" className="p-8 text-sm text-severity-critical-fg">
        Could not load this session.
      </p>
    )
  }

  const analysis = latestByDate(query.data.analyses)
  if (!analysis) {
    return <p className="p-8 text-muted">No analysis yet.</p>
  }

  return (
    <AnalysisScreen
      projectId={sessionId}
      analysis={analysis}
      onChanged={() => void queryClient.invalidateQueries({ queryKey: ["project", sessionId] })}
    />
  )
}
