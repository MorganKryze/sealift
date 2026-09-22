import { useQuery } from "@tanstack/react-query"
import { SessionLoadError } from "@/components/route-error"
import { createFileRoute, Outlet } from "@tanstack/react-router"

import { getProject } from "@/api/projects"
import { isJobActive, JOB_POLL_INTERVAL_MS, latestByDate } from "@/lib/utils"

export const Route = createFileRoute("/sessions/$sessionId")({
  component: SessionLayout,
})

/**
 * Shared loading and error boundary for every step of one session. Each
 * step route queries the same ["project", sessionId] cache entry itself
 * (react-query dedups the concurrent request), so this layout only needs
 * to keep the session polling while a job is active and render its Outlet.
 */
function SessionLayout() {
  const { sessionId } = Route.useParams()

  const query = useQuery({
    queryKey: ["project", sessionId],
    queryFn: () => getProject(sessionId),
    refetchInterval: (q) => {
      const project = q.state.data
      const active = isJobActive(latestByDate(project?.analyses)) || isJobActive(latestByDate(project?.exports))
      return active ? JOB_POLL_INTERVAL_MS : false
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
    return <SessionLoadError error={query.error} onRetry={() => void query.refetch()} />
  }

  return <Outlet />
}
