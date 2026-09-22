import { useQuery } from "@tanstack/react-query"
import { createFileRoute, Navigate } from "@tanstack/react-router"

import { getProject } from "@/api/projects"
import { latestByDate } from "@/lib/utils"

export const Route = createFileRoute("/sessions/$sessionId/")({
  component: SessionIndexRoute,
})

/**
 * "/sessions/$sessionId" alone has no screen of its own: it lands on
 * whichever step the session is actually at, so a bookmarked or shared
 * session link (and "Resume that session") always opens somewhere useful.
 */
function SessionIndexRoute() {
  const { sessionId } = Route.useParams()
  const query = useQuery({ queryKey: ["project", sessionId], queryFn: () => getProject(sessionId) })

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

  const lastAnalysis = latestByDate(query.data.analyses)
  if (lastAnalysis && lastAnalysis.state === "done") {
    return <Navigate to="/sessions/$sessionId/review" params={{ sessionId }} replace />
  }
  return <Navigate to="/sessions/$sessionId/analysis" params={{ sessionId }} replace />
}
