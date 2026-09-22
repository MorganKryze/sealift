import type { Project } from "@/api/projects"
import { stepBarStep, type StepBarStep, type StepId } from "@/components/step-bar"
import { latestByDate } from "@/lib/utils"

export const TERMINAL_FAILED_STATES = new Set(["failed", "cancelled", "interrupted"])

interface SessionStepsOptions {
  project: Project
  /** The step the caller is actually rendering; always shown as "current", never a link. */
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

  const dropStatus = current === "drop" ? "current" : "done"
  const analysisStatus =
    current === "analysis"
      ? "current"
      : !analysis
        ? "upcoming"
        : TERMINAL_FAILED_STATES.has(analysis.state)
          ? "failed"
          : "done"
  const reviewStatus =
    current === "review" ? "current" : analysis?.state === "done" ? "done" : "upcoming"
  const exportStatus =
    current === "export"
      ? "current"
      : !relatedExport
        ? "upcoming"
        : TERMINAL_FAILED_STATES.has(relatedExport.state)
          ? "failed"
          : "done"

  const nav = (step: StepId, status: StepBarStep["status"]) =>
    status === "current" || status === "upcoming" ? undefined : () => onNavigate(step)

  return [
    stepBarStep("drop", dropStatus, nav("drop", dropStatus)),
    stepBarStep("analysis", analysisStatus, nav("analysis", analysisStatus)),
    stepBarStep("review", reviewStatus, nav("review", reviewStatus)),
    stepBarStep("export", exportStatus, nav("export", exportStatus)),
  ]
}
