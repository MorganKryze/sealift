import type { Analysis, Project } from "@/api/projects"
import { stepBarStep, type StepBarStep, type StepId, type StepStatus } from "@/components/step-bar"
import { latestByDate } from "@/lib/utils"

export const TERMINAL_FAILED_STATES = new Set(["failed", "cancelled", "interrupted"])

interface SessionStepsOptions {
  project: Project
  /** The step the caller is rendering: flagged current, never a link to itself. */
  current: StepId
  /** The analysis the screen shows (`?analysis=`); the latest one when the screen names none. */
  analysis?: Analysis
  onNavigate: (step: StepId) => void
}

/**
 * The four-step bar for every session screen, computed from the project's
 * own analysis and export history. A step already reached must stay
 * navigable, so this is the one place that decides "done" versus
 * "upcoming" instead of each route repeating the rule and drifting: the
 * uploaded file has no route of its own once a session exists (drop is
 * client-only state on the home screen), but everything reached after it
 * is a real step this session's project data can still show.
 */
export function sessionSteps({ project, analysis: shown, current, onNavigate }: SessionStepsOptions): StepBarStep[] {
  const analysis = shown ?? latestByDate(project.analyses)
  const relatedExport = analysis
    ? latestByDate(project.exports?.filter((candidate) => candidate.analysisId === analysis.id))
    : undefined

  const isCurrent = (step: StepId) => step === current

  // A cancel is the developer's own stop, never a failure. A cancelled export leaves nothing sealed, so
  // Seal is still to do and Review is where the developer goes back to.
  const analysisStatus: StepStatus = !analysis
    ? "upcoming"
    : analysis.state === "cancelled"
      ? "cancelled"
      : TERMINAL_FAILED_STATES.has(analysis.state)
        ? "failed"
        : analysis.state === "done"
          ? "done"
          : "running"
  const exported = relatedExport && relatedExport.state !== "cancelled" ? relatedExport : undefined
  const reviewStatus: StepStatus = analysis?.state !== "done" ? "upcoming" : exported ? "done" : "available"
  const exportStatus: StepStatus = !exported
    ? "upcoming"
    : TERMINAL_FAILED_STATES.has(exported.state)
      ? "failed"
      : exported.state === "done"
        ? "done"
        : "running"

  const step = (id: StepId, status: StepStatus) =>
    stepBarStep(id, status, isCurrent(id), status === "upcoming" || isCurrent(id) ? undefined : () => onNavigate(id))

  return [step("drop", "done"), step("analysis", analysisStatus), step("review", reviewStatus), step("export", exportStatus)]
}
