import type { Project } from "@/api/projects"
import { stepBarStep, type StepBarStep, type StepId, type StepStatus } from "@/components/step-bar"
import { latestByDate } from "@/lib/utils"

export const TERMINAL_FAILED_STATES = new Set(["failed", "cancelled", "interrupted"])

interface SessionStepsOptions {
  project: Project
  /** The step the caller is rendering: flagged current, never a link to itself. */
  current: StepId
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
export function sessionSteps({ project, current, onNavigate }: SessionStepsOptions): StepBarStep[] {
  const analysis = latestByDate(project.analyses)
  const relatedExport = analysis
    ? latestByDate(project.exports?.filter((candidate) => candidate.analysisId === analysis.id))
    : undefined

  const isCurrent = (step: StepId) => step === current

  const analysisStatus: StepStatus = !analysis
    ? "upcoming"
    : TERMINAL_FAILED_STATES.has(analysis.state)
      ? "failed"
      : analysis.state === "done"
        ? "done"
        : "running"
  const reviewStatus: StepStatus = analysis?.state !== "done" ? "upcoming" : relatedExport ? "done" : "available"
  const exportStatus: StepStatus = !relatedExport
    ? "upcoming"
    : TERMINAL_FAILED_STATES.has(relatedExport.state)
      ? "failed"
      : relatedExport.state === "done"
        ? "done"
        : "running"

  const step = (id: StepId, status: StepStatus) =>
    stepBarStep(id, status, isCurrent(id), status === "upcoming" || isCurrent(id) ? undefined : () => onNavigate(id))

  return [step("drop", "done"), step("analysis", analysisStatus), step("review", reviewStatus), step("export", exportStatus)]
}
