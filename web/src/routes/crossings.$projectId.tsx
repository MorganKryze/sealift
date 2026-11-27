import { useQuery, useQueryClient } from "@tanstack/react-query"
import { createFileRoute, useNavigate } from "@tanstack/react-router"

import { getProject, getProjectManifest, type Analysis, type Project } from "@/api/projects"
import { SessionLoadError } from "@/components/route-error"
import { AnalysisScreen } from "@/components/session/analysis-screen"
import { CheckBlock } from "@/components/session/check-block"
import { ExportScreen } from "@/components/session/export-screen"
import { PipCrossingCheck, PipReviewScreen } from "@/components/session/pip-review-screen"
import { ReviewScreen } from "@/components/session/review-screen"
import { StepBar, type StepId } from "@/components/step-bar"
import { Button } from "@/components/ui/button"
import { parseManifestPreview } from "@/lib/manifestPreview"
import { analysisSearch, shownAnalysis } from "@/lib/session-analysis"
import { sessionSteps } from "@/lib/sessionSteps"
import { isJobActive, JOB_POLL_INTERVAL_MS, latestByDate } from "@/lib/utils"

/** The analysis a crossing link names, when it is not the latest, and the step it goes back to. */
export type CrossingSearch = { analysis?: string; step?: "check" | "review" }

/** Keeps a non-empty id and a known step only, so a hand-edited link falls back to the latest analysis at its state's step. */
export function crossingSearch(search: Record<string, unknown>): CrossingSearch {
  const step = search.step === "check" || search.step === "review" ? search.step : undefined
  return { ...analysisSearch(search), ...(step ? { step } : {}) }
}

export const Route = createFileRoute("/crossings/$projectId")({
  validateSearch: crossingSearch,
  component: CrossingRoute,
})

/** The exports of one analysis: the latest, and the last done one when the latest is not. */
function exportsOf(project: Project | undefined, analysisId: string | undefined) {
  const list = analysisId ? project?.exports?.filter((candidate) => candidate.analysisId === analysisId) : undefined
  const latest = latestByDate(list)
  // A later export that failed must not hide an archive this analysis already produced: it is still on disk.
  const previous = latest && latest.state !== "done" ? latestByDate(list?.filter((candidate) => candidate.state === "done")) : undefined
  return { latest, previous }
}

/**
 * One crossing at one address, on the step its state has reached: Analyse while its analysis has not
 * finished, Review once it has, Seal while an export of it runs, failed or finished. A cancelled export
 * returns to Review. The search names Check or Review when the developer goes back to them.
 */
function CrossingRoute() {
  const { projectId } = Route.useParams()
  const { analysis: analysisId, step } = Route.useSearch()
  const navigate = useNavigate()
  const queryClient = useQueryClient()

  const query = useQuery({
    queryKey: ["project", projectId],
    queryFn: () => getProject(projectId),
    refetchInterval: (q) => {
      const analysis = shownAnalysis(q.state.data?.analyses, analysisId)
      return isJobActive(analysis) || isJobActive(exportsOf(q.state.data, analysis?.id).latest) ? JOB_POLL_INTERVAL_MS : false
    },
  })

  if (query.isPending) {
    return (
      <div role="status" className="flex flex-1 items-center justify-center p-8 text-muted">
        Loading crossing…
      </div>
    )
  }

  if (query.isError) {
    return <SessionLoadError error={query.error} onRetry={() => void query.refetch()} />
  }

  const project = query.data
  const analysis = shownAnalysis(project.analyses, analysisId)
  // The address keeps naming the analysis it was opened on, so a step change stays on that crossing.
  const named = analysis && analysis.id === analysisId ? analysisId : undefined

  function goToStep(target: StepId) {
    const to = target === "drop" ? "check" : target === "review" ? "review" : undefined
    void navigate({ to: "/crossings/$projectId", params: { projectId }, search: { ...(named ? { analysis: named } : {}), ...(to ? { step: to } : {}) } })
  }

  const onChanged = () => void queryClient.invalidateQueries({ queryKey: ["project", projectId] })

  const pip = project.ecosystem === "pip"
  if (step === "check" || !analysis) {
    if (pip) return <PipCrossingCheck project={project} analysis={analysis} onNavigateStep={goToStep} />
    return <CheckStep project={project} analysis={analysis} onNavigateStep={goToStep} />
  }

  if (step !== "review" && analysis.state !== "done") {
    return (
      // A retry queues a new analysis with a new id: a fresh key remounts the screen and its event stream.
      <AnalysisScreen key={analysis.id} projectId={projectId} project={project} analysis={analysis} onChanged={onChanged} onNavigateStep={goToStep} />
    )
  }

  const exports = exportsOf(project, analysis.id)
  if (step !== "review" && exports.latest && exports.latest.state !== "cancelled") {
    return (
      <ExportScreen
        key={analysis.id}
        project={project}
        analysis={analysis}
        relatedExport={exports.latest}
        previousArchive={exports.previous}
        onChanged={onChanged}
        onNavigateStep={goToStep}
      />
    )
  }

  if (pip) {
    return <PipReviewScreen key={analysis.id} project={project} analysis={analysis} onNavigateStep={goToStep} />
  }
  return <ReviewScreen key={analysis.id} project={project} analysis={analysis} onNavigateStep={goToStep} />
}

/** The Check step read back: the package.json the server stored, with no file to replace. */
function CheckStep({ project, analysis, onNavigateStep }: { project: Project; analysis?: Analysis; onNavigateStep: (step: StepId) => void }) {
  // The same entry Review's Decide reads, so going back and forth asks once.
  const manifestQuery = useQuery({
    queryKey: ["project", project.id, "manifest"],
    queryFn: () => getProjectManifest(project.id),
    staleTime: Infinity,
  })
  const manifest = (() => {
    if (!manifestQuery.data) return undefined
    try {
      return parseManifestPreview(manifestQuery.data, project.name)
    } catch {
      return undefined
    }
  })()
  const steps = sessionSteps({ project, analysis, current: "drop", onNavigate: onNavigateStep })

  return (
    <div className="animate-enter mx-auto flex w-full max-w-190 flex-1 flex-col px-5 py-9">
      <StepBar steps={steps} />
      <h1 className="mb-5 text-[28px] font-bold tracking-tight text-ink [overflow-wrap:anywhere]">{`Update ${manifest?.name ?? project.name}`}</h1>
      {manifest ? (
        <CheckBlock manifest={manifest} />
      ) : manifestQuery.isPending ? (
        <p role="status" className="text-muted">
          Reading the package.json…
        </p>
      ) : (
        <div className="flex flex-wrap items-center justify-between gap-3 tinted-bad px-4 py-3">
          <p className="text-ink">This crossing&apos;s package.json did not load.</p>
          <Button variant="outline" onClick={() => void manifestQuery.refetch()}>
            Retry
          </Button>
        </div>
      )}
    </div>
  )
}
