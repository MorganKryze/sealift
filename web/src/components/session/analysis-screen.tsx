import { useMutation } from "@tanstack/react-query"
import { useNavigate } from "@tanstack/react-router"
import { Check, Loader2, X } from "lucide-react"
import { useState } from "react"

import { ApiError } from "@/api/client"
import { cancelAnalysis, queueAnalysis, type Analysis, type Project } from "@/api/projects"
import { FailureBlock } from "@/components/failure-block"
import { ProblemNotice } from "@/components/problem-notice"
import { StepBar, type StepId } from "@/components/step-bar"
import { useSettingsPanel } from "@/components/settings/settings-panel"
import { Button } from "@/components/ui/button"
import { Card } from "@/components/ui/card"
import { Progress } from "@/components/ui/progress"
import { useJobEvents } from "@/hooks/use-job-events"
import { sessionSteps, TERMINAL_FAILED_STATES } from "@/lib/sessionSteps"
import { formatDuration } from "@/lib/utils"

interface AnalysisScreenProps {
  projectId: string
  project: Project
  analysis: Analysis
  /** Refetches the project so the route sees the next analysis or its result. */
  onChanged: () => void
  onNavigateStep: (step: StepId) => void
}

// Mirrors the step names internal/jobs/analysis_steps.go, analysis_candidates.go
// and analysis_rank.go emit, in run order. A step this run never reaches
// just stays at its upcoming dot; runStep always emits exactly one event
// per step it does reach, done or failed.
const ANALYSIS_STEPS: { id: string; label: string }[] = [
  { id: "validate", label: "Check the manifest" },
  { id: "prepare-tools", label: "Prepare pnpm and Trivy" },
  { id: "resolve-project", label: "Resolve the project" },
  { id: "scan-project", label: "Scan for known CVEs" },
  { id: "list-candidates", label: "List newer versions" },
  { id: "resolve-candidates", label: "Resolve candidate versions" },
  { id: "scan-candidates", label: "Scan candidate versions" },
  { id: "rank", label: "Rank and propose" },
  { id: "check-combined", label: "Check the combined install" },
]

/**
 * The cause shown for a stopped analysis. An analysis run before sealift
 * recorded causes has a failure with an empty message; it still names the
 * step, so the screen says where it stopped and points at the log.
 */
export function failureMessage(analysis: Pick<Analysis, "state" | "failure">): string {
  // A cancel stops the run with a "context canceled" error: the user's own action, not a failure.
  if (analysis.state === "cancelled") return "You cancelled this analysis."
  const cause = analysis.failure?.message?.trim()
  if (cause) return cause
  if (analysis.failure) {
    const step = ANALYSIS_STEPS.find((s) => s.id === analysis.failure?.step)?.label ?? analysis.failure.step
    return `It stopped at "${step}". The version of sealift that ran it did not record why; the log below has what it wrote.`
  }
  return "The analysis was interrupted, most likely by a server restart."
}

export function AnalysisScreen({ projectId, project, analysis, onChanged, onNavigateStep }: AnalysisScreenProps) {
  const settingsPanel = useSettingsPanel()
  const navigate = useNavigate()
  const [cancelling, setCancelling] = useState(false)
  const [cancelError, setCancelError] = useState<ApiError | null>(null)

  const live = analysis.state === "queued" || analysis.state === "running"
  const events = useJobEvents(analysis.id, live, onChanged)
  const failedState = TERMINAL_FAILED_STATES.has(analysis.state)
  const showSteps = live || events.steps.length > 0
  const eventsByName = new Map(events.steps.map((step) => [step.name, step]))
  // scan-candidates (the step right after) also reports progress, in two
  // fixed batches; reading resolve-candidates' own entry instead of the
  // latest progress event keeps its real count on screen once scanning
  // starts, rather than a stale "2 of 2" once the run has moved on.
  const resolveProgress = events.progressByStep["resolve-candidates"]

  const retryMutation = useMutation({
    mutationFn: () => queueAnalysis(projectId),
    onSuccess: onChanged,
  })
  const retryError = retryMutation.error instanceof ApiError ? retryMutation.error : null

  async function handleCancel() {
    if (!window.confirm("Cancel this analysis?")) {
      return
    }
    setCancelling(true)
    setCancelError(null)
    try {
      await cancelAnalysis(projectId, analysis.id)
      onChanged()
    } catch (error) {
      setCancelError(error instanceof ApiError ? error : null)
    } finally {
      setCancelling(false)
    }
  }

  const steps = sessionSteps({ project, current: "analysis", onNavigate: onNavigateStep })

  const title = failedState
    ? analysis.state === "failed"
      ? "Analysis stopped"
      : analysis.state === "cancelled"
        ? "Analysis cancelled"
        : "Analysis interrupted"
    : analysis.state === "done"
      ? "Analysis finished"
      : "Analysing"

  const lead = failedState
    ? "The cause and the next action are below."
    : analysis.state === "done"
      ? "sealift picked a version for each dependency."
      : "Resolving each candidate against the whole project takes most of the time. You can leave this page; the session keeps running."

  const elapsedMs = events.steps.reduce((sum, step) => sum + (step.durationMs ?? 0), 0)

  return (
    <div className="animate-enter mx-auto flex w-full max-w-240 flex-1 flex-col px-5 py-8">
      <StepBar steps={steps} />

      <div className="mb-6">
        <h1 className="text-2xl font-bold tracking-tight text-ink">{title}</h1>
        <p className="mt-1.5 max-w-[62ch] text-muted">{lead}</p>
      </div>

      {showSteps ? (
        <Card>
          <ol className="py-1.5">
            {ANALYSIS_STEPS.map((step, index) => {
              const entry = eventsByName.get(step.id)
              const state = entry?.state ?? ""
              return (
                <li
                  key={step.id}
                  className="grid grid-cols-[22px_1fr_auto] items-center gap-3 px-5.5 py-2.5 text-sm text-muted"
                >
                  <span
                    className={
                      "grid size-5.5 place-items-center rounded-full border " +
                      (state === "done"
                        ? "animate-pop border-accent bg-accent text-background"
                        : state === "failed"
                          ? "animate-pop border-severity-critical bg-severity-critical text-white"
                          : state === "running"
                            ? "border-accent text-accent"
                            : "border-line text-muted")
                    }
                  >
                    {state === "done" ? (
                      <Check className="size-3" strokeWidth={3} />
                    ) : state === "failed" ? (
                      <X className="size-3" strokeWidth={3} />
                    ) : state === "running" ? (
                      <Loader2 className="size-3 animate-spin" />
                    ) : (
                      <span className="text-[10px] font-semibold">{index + 1}</span>
                    )}
                  </span>
                  <span className={state ? "text-ink" : "text-muted"}>
                    {step.label}
                    {entry?.error ? <span className="block text-xs text-severity-critical-fg">{entry.error}</span> : null}
                  </span>
                  <span className="font-mono text-xs text-muted">
                    {entry?.durationMs !== undefined ? formatDuration(entry.durationMs) : ""}
                  </span>
                </li>
              )
            })}
          </ol>
          <div hidden={!resolveProgress} className="border-t border-line px-5.5 py-3.5">
            <div className="flex justify-between text-xs text-muted tabular-nums">
              <span>
                {resolveProgress ? `${resolveProgress.done} of ${resolveProgress.total} candidates resolved` : ""}
              </span>
              <span>
                {resolveProgress?.estimatedRemainingMs !== undefined
                  ? `about ${formatDuration(resolveProgress.estimatedRemainingMs)} left`
                  : ""}
              </span>
            </div>
            <Progress
              className="mt-2.5"
              value={resolveProgress && resolveProgress.total > 0 ? (resolveProgress.done / resolveProgress.total) * 100 : 0}
              label="Candidates resolved"
            />
          </div>
        </Card>
      ) : null}

      {live ? (
        <div className="mt-5 flex flex-col items-start gap-2">
          <Button variant="outline" onClick={() => void handleCancel()} disabled={cancelling}>
            Cancel
          </Button>
          {cancelError ? <ProblemNotice status={cancelError.status} problem={cancelError.problem} /> : null}
        </div>
      ) : null}

      {analysis.state === "done" ? (
        <div className="animate-enter mt-5 flex items-center gap-3">
          <Button
            size="lg"
            onClick={() => void navigate({ to: "/sessions/$sessionId/review", params: { sessionId: projectId } })}
          >
            Review the proposal
          </Button>
          {elapsedMs > 0 ? <span className="text-sm text-muted">Finished in {formatDuration(elapsedMs)}</span> : null}
        </div>
      ) : null}

      {failedState ? (
        <FailureBlock
          projectId={projectId}
          analysisId={analysis.id}
          heading="What went wrong"
          message={failureMessage(analysis)}
          detail="Your uploaded file is kept. Retrying starts a new analysis from the beginning."
          actions={
            <>
              <Button onClick={() => retryMutation.mutate()} disabled={retryMutation.isPending}>
                Retry
              </Button>
              <Button variant="outline" onClick={settingsPanel.open}>
                Open settings
              </Button>
              <Button variant="ghost" onClick={() => void navigate({ to: "/" })}>
                Choose another file
              </Button>
            </>
          }
        />
      ) : null}
      {retryError ? <ProblemNotice status={retryError.status} problem={retryError.problem} className="mt-4" /> : null}
    </div>
  )
}
