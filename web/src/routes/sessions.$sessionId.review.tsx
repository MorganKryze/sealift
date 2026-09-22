import { useQuery } from "@tanstack/react-query"
import { createFileRoute, useNavigate } from "@tanstack/react-router"

import { getProject } from "@/api/projects"
import { ReviewScreen } from "@/components/session/review-screen"
import type { StepId } from "@/components/step-bar"
import { latestByDate } from "@/lib/utils"

export const Route = createFileRoute("/sessions/$sessionId/review")({
  component: ReviewRoute,
})

function ReviewRoute() {
  const { sessionId } = Route.useParams()
  const navigate = useNavigate()

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

  const project = query.data
  const analysis = latestByDate(project.analyses)

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

  return <ReviewScreen project={project} analysis={analysis} onNavigateStep={goToStep} />
}
