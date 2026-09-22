import { useQuery } from "@tanstack/react-query"
import { createFileRoute, useNavigate } from "@tanstack/react-router"

import { getProject } from "@/api/projects"
import { AnalysisResults } from "@/components/projects/analysis-results"
import { stepBarStep, StepBar, type StepBarStep } from "@/components/step-bar"
import { latestByDate } from "@/lib/utils"

export const Route = createFileRoute("/sessions/$sessionId/review")({
  component: ReviewRoute,
})

// Task 10 replaces this screen's body with the full grouped proposal from
// the prototype's Review step; until then it reuses the existing results
// view and hands off to the existing export route, both left working.
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
  const steps: StepBarStep[] = [
    stepBarStep("drop", "done"),
    stepBarStep("analysis", "done", () => void navigate({ to: "/sessions/$sessionId/analysis", params: { sessionId } })),
    stepBarStep("review", "current"),
    stepBarStep("export", "upcoming"),
  ]

  return (
    <div className="animate-enter mx-auto flex w-full max-w-240 flex-1 flex-col px-5 py-8">
      <StepBar steps={steps} />
      {!analysis || analysis.state !== "done" || !analysis.result ? (
        <p className="p-8 text-muted">No finished analysis to review yet.</p>
      ) : (
        <AnalysisResults
          analysisId={analysis.id}
          result={analysis.result}
          trivyVersion={analysis.trivyVersion}
          trivyDbDate={analysis.trivyDbDate}
          pnpmVersion={analysis.pnpmVersion}
          onContinue={() =>
            void navigate({
              to: "/projects/$projectId/analyses/$analysisId/export",
              params: { projectId: sessionId, analysisId: analysis.id },
            })
          }
        />
      )}
    </div>
  )
}
