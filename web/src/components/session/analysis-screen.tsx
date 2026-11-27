import { useMutation, useQuery } from "@tanstack/react-query"
import { Link } from "@tanstack/react-router"
import { ArrowRight, FileUp, LoaderCircle, RotateCcw } from "lucide-react"
import { useEffect, useRef, useState, type ReactNode } from "react"

import { ApiError } from "@/api/client"
import { cancelAnalysis, listProjects, queueAnalysis, type Analysis, type Project, type ProjectSummary } from "@/api/projects"
import { FailureBlock, type FailureCause } from "@/components/failure-block"
import { CancelRow, JobProgress, type CancelWords } from "@/components/job-progress"
import { ProblemNotice } from "@/components/problem-notice"
import { StepBar, type StepId } from "@/components/step-bar"
import { Button } from "@/components/ui/button"
import { useJobEvents } from "@/hooks/use-job-events"
import { about, currentStep, elapsed, estimateOf, timeLeft, type AnalysisEventsState } from "@/lib/analysisEvents"
import { crossingName } from "@/lib/crossings"
import { sessionSteps } from "@/lib/sessionSteps"
import { JOB_POLL_INTERVAL_MS } from "@/lib/utils"

interface AnalysisScreenProps {
  projectId: string
  project: Project
  analysis: Analysis
  /** Refetches the project so the route sees the next analysis or its result. */
  onChanged: () => void
  onNavigateStep: (step: StepId) => void
}

// What each step of internal/jobs' analysis does while it runs, by the name its step event carries.
const DOING: Record<string, string> = {
  validate: "Checking the package.json",
  "prepare-tools": "Preparing pnpm and Trivy",
  "resolve-project": "Resolving the project",
  "scan-project": "Scanning the project",
  "list-candidates": "Listing newer versions",
  "resolve-candidates": "Trying newer versions",
  "scan-candidates": "Scanning the newer versions",
  rank: "Ranking the versions",
  "check-combined": "Checking the proposal as one install",
}

// The same for a pip analysis, whose steps internal/jobs names in this run order.
const PIP_DOING: Record<string, string> = {
  validate: "Reading the requirements files",
  "prepare-tools": "Preparing uv and the CVE database",
  "check-pins": "Checking a wheel for each pin",
  resolve: "Resolving the set",
  "choose-wheels": "Choosing a wheel per package",
  scan: "Scanning for known CVEs",
}
const PIP_ORDER = Object.keys(PIP_DOING)

const doing = (step: string | undefined, pip = false) => (step ? ((pip ? PIP_DOING : DOING)[step] ?? `Running ${step}`) : "Finishing the analysis")

/** The pip step running now: a step reports itself when it ends, so the one running is the next one. */
function pipStep(steps: AnalysisEventsState["steps"]): string | undefined {
  const last = steps.at(-1)
  if (!last) return PIP_ORDER[0]
  if (last.state !== "done") return last.name
  return PIP_ORDER[PIP_ORDER.indexOf(last.name) + 1]
}

/** What the index says of a version with no wheel for the target, by the kind the analysis records. */
export const PUBLISHES: Record<string, string> = {
  "source-only": "Publishes a source distribution only.",
  "other-platforms": "Publishes wheels for other platforms only.",
  "no-files": "Publishes no file for this version.",
  "hash-mismatch": "Its --hash options list no wheel this target installs.",
}

// internal/jobs words a validate failure "<n> problems in the requirements files: <place>: <line>: <reason>; ...",
// each place "<file> line <n>" or "<file>" alone, and ends a long list with "the log lists the rest".
function requirementsProblems(message: string): FailureCause | undefined {
  const head = message.match(/^(\d+) (problems?) in the requirements files: ([\s\S]*)$/)
  if (!head) return undefined
  const items = head[3]
    .split("; ")
    .filter((part) => part !== "the log lists the rest")
    .map((part) => {
      // A reason may hold ": " itself, so the place and the line as written are read from the left.
      const place = part.match(/^(.+? line \d+|[^:]+): ([\s\S]*)$/)
      if (!place) return { name: part, value: "" }
      const text = place[2].match(/^([^\s:]+|[^:]*[=<>~@][^:]*): ([\s\S]+)$/)
      return text ? { name: `${place[1]}: ${text[1]}`, value: text[2] } : { name: place[1], value: place[2] }
    })
  return {
    title: `${head[1]} ${head[2]} in the requirements files`,
    items,
    diagnosis: "A retry gives the same answer: the lines come from your requirements files.",
  }
}

/** The pip causes: problems in the files, a package with no wheel, no answer from the index, else the sentence. */
function pipCause(analysis: Pick<Analysis, "failure" | "pipResult">, message: string, step: string): FailureCause & { action: "retry" | "replace" } {
  if (analysis.failure?.step === "validate") {
    const problems = requirementsProblems(message)
    if (problems) return { ...problems, action: "replace" }
  }
  const blocking = analysis.pipResult?.blocking ?? []
  if (blocking.length > 0) {
    return {
      title: blocking.length === 1 ? "A package has no wheel for the target" : `${blocking.length.toLocaleString("en-US")} packages have no wheel for the target`,
      count: `${blocking.length.toLocaleString("en-US")} ${blocking.length === 1 ? "package" : "packages"}`,
      items: blocking.map((b) => ({ name: b.name, value: b.version })),
      diagnosis: `${blocking.map((b) => `${b.name} ${(PUBLISHES[b.kind] ?? "Publishes no wheel for the target.").replace(/^P/, "p")}`).join(" ")} A retry gives the same answer: the version comes from your requirements files.`,
      action: "replace",
    }
  }
  if (/database/i.test(message)) {
    return { title: "The vulnerability database did not download", diagnosis: `The scan needs it, so the analysis stopped while ${step}. Your requirements files are not the cause.`, action: "retry" }
  }
  if (NO_ANSWER.test(message)) {
    return {
      title: `No answer from ${hostIn(message) ?? "the index"}`,
      diagnosis: `The fetch timed out or was refused while ${step}. Your requirements files passed their checks, so the files are not the cause.`,
      action: "retry",
    }
  }
  return { title: message.split("\n")[0], diagnosis: `It stopped while ${step}. The log has the whole message.`, action: "retry" }
}
const lower = (words: string) => words.charAt(0).toLowerCase() + words.slice(1)

const COUNT = new Intl.NumberFormat("en-GB")
const figure = (n: number) => <span className="figure text-ink">{COUNT.format(n)}</span>

/** "212 of 486 newer versions tried", the figures in weight 600. */
function triedOf(state: AnalysisEventsState, step: string, what: string): ReactNode {
  const progress = state.progressByStep[step]
  if (!progress) return undefined
  return (
    <>
      {figure(progress.done)} of {figure(progress.total)} {what}
    </>
  )
}

/**
 * The cause of a stopped analysis as one sentence. An analysis run before causes were recorded has a
 * failure with an empty message; it still names its step, so the sentence says where it stopped.
 */
export function failureMessage(analysis: Pick<Analysis, "state" | "failure">, pip = false): string {
  if (analysis.state === "cancelled") return "You cancelled this analysis."
  const cause = analysis.failure?.message?.trim()
  if (cause) return cause
  if (analysis.failure) return `It stopped while ${lower(doing(analysis.failure.step, pip))}. The version that ran it did not record why; the log has what it wrote.`
  return "The server restarted while it ran."
}

export const NO_ANSWER = /ETIMEDOUT|ESOCKETTIMEDOUT|ERR_SOCKET_TIMEOUT|ECONNREFUSED|ECONNRESET|ENOTFOUND|EAI_AGAIN|ERR_PNPM_META_FETCH_FAIL|timed out|timeout|connection refused|no such host|deadline exceeded/i

// The host a failed fetch names: the first URL's, else the one a name lookup failed on.
export function hostIn(message: string): string | undefined {
  return message.match(/https?:\/\/([^/\s:@]+)/)?.[1] ?? message.match(/lookup ([^\s:]+)/)?.[1]
}

/**
 * What stopped an analysis, in words, and the one action that clears it: a version the registry lacks
 * needs a new package.json, a fetch with no answer or anything else a retry, a cancel or a restart a
 * new start. An unmapped cause reads as the tool wrote it, shortened to its first line.
 */
export function analysisCause(
  analysis: Pick<Analysis, "state" | "failure" | "pipResult">,
  ecosystem: Project["ecosystem"] = "npm",
): FailureCause & { action: "retry" | "replace" | "start-again" } {
  const pip = ecosystem === "pip"
  const kept = pip ? "Your requirements files are kept." : "Your package.json is kept."
  if (analysis.state === "cancelled") return { title: "You cancelled this analysis", diagnosis: kept, action: "start-again" }
  const failure = analysis.failure
  if (!failure) return { title: "The server restarted while it ran", diagnosis: kept, action: "start-again" }
  const message = failure.message?.trim() ?? ""
  const step = lower(doing(failure.step, pip))
  if (!message) return { title: "The cause was not recorded", diagnosis: failureMessage(analysis, pip), action: "retry" }
  if (pip) return pipCause(analysis, message, step)
  if (message.includes("ERR_PNPM_NO_MATCHING_VERSION")) {
    const pinned = message.match(/No matching version found for ((?:@[^\s/@]+\/)?[^\s@]+)@([^\s:,]+)/)
    return {
      title: "A pinned version is not on npm",
      ...(pinned ? { count: "1 package", items: [{ name: pinned[1], value: pinned[2] }] } : {}),
      diagnosis: "A retry gives the same answer: the version comes from your package.json.",
      action: "replace",
    }
  }
  if (/database/i.test(message)) {
    return { title: "The vulnerability database did not download", diagnosis: `The scan needs it, so the analysis stopped while ${step}. Your package.json is not the cause.`, action: "retry" }
  }
  if (NO_ANSWER.test(message)) {
    return {
      title: `No answer from ${hostIn(message) ?? "the registry"}`,
      diagnosis: `The fetch timed out or was refused while ${step}. Your package.json passed its checks, so the file is not the cause.`,
      action: "retry",
    }
  }
  return { title: message.split("\n")[0], diagnosis: `It stopped while ${step}. The log has the whole message.`, action: "retry" }
}

/** The job that runs now, from the projects list: its crossing's name, its store id and what it is. */
function runningNow(projects: ProjectSummary[], ownId: string) {
  for (const project of projects) {
    const analysis = project.lastAnalysis
    const name = analysis ? crossingName(project.name, analysis, [analysis]) : project.name
    if (analysis?.state === "running" && analysis.id !== ownId) return { projectId: project.id, name, storeId: analysis.id, kind: "analysis" as const }
    if (project.lastExport?.state === "running") return { projectId: project.id, name, storeId: project.lastExport.id, kind: "export" as const }
  }
  return undefined
}

// The queue's order is in no answer: a job queued before this one, by its creation time, means more than one wait.
function waitsBehind(projects: ProjectSummary[], analysis: Analysis): boolean {
  const queuedAt = new Date(analysis.createdAt).getTime()
  const before = (job?: { id: string; state: string; createdAt: string }) =>
    job?.state === "queued" && job.id !== analysis.id && new Date(job.createdAt).getTime() < queuedAt
  return projects.some((project) => before(project.lastAnalysis) || before(project.lastExport))
}

function QueuedAnalysis({ analysis, cancel }: { analysis: Analysis; cancel: CancelWords }) {
  const projectsQuery = useQuery({ queryKey: ["projects"], queryFn: () => listProjects(), refetchInterval: JOB_POLL_INTERVAL_MS })
  const projects = projectsQuery.data ?? []
  const running = runningNow(projects, analysis.id)
  const runEvents = useJobEvents(running?.storeId ?? "", Boolean(running), () => void projectsQuery.refetch())
  const estimate = running ? estimateOf(runEvents) : undefined
  const title = estimate !== undefined && !waitsBehind(projects, analysis) ? `Starts in ${about(estimate)}` : "Waits for the running job"
  const counted = running?.kind === "export" ? triedOf(runEvents, "download", "packages downloaded") : triedOf(runEvents, "resolve-candidates", "newer versions tried")

  return (
    <div>
      <h1 aria-live="polite" className="text-[34px] leading-tight font-bold tracking-tight text-ink">
        {title}
      </h1>
      <p className="mt-1.5 text-[15px] text-muted">One job runs at a time.</p>
      {running ? (
        <>
          <p className="mt-6 mb-2 text-xs font-semibold text-muted">Running now</p>
          <ul>
            <li className="flex flex-wrap items-center gap-x-3 gap-y-2 rounded-xl border border-rule px-3.5 py-3">
              <span className="tinted-info grid size-8 flex-none place-items-center">
                <LoaderCircle aria-hidden="true" className="size-4 text-info" />
              </span>
              <div className="min-w-0 flex-1">
                <span className="block font-semibold text-ink [overflow-wrap:anywhere]">{running.name}</span>
                <div className="flex flex-wrap items-center gap-x-2">
                  <span className="tinted-info rounded-full px-2 text-xs leading-5 font-semibold text-info">{running.kind === "export" ? "Sealing" : "Analysing"}</span>
                  {counted ? <p className="text-[13px] text-muted">{counted}</p> : null}
                </div>
              </div>
              <Button asChild variant="outline">
                <Link to="/crossings/$projectId" params={{ projectId: running.projectId }} aria-label={`Open ${running.name}`}>
                  Open
                </Link>
              </Button>
            </li>
          </ul>
        </>
      ) : null}
      <CancelRow note="Keeps its place if you leave this page" cancel={cancel} />
    </div>
  )
}

/**
 * The Analyse step: a queued analysis says when it starts, a running one its time left, what it counts
 * and its live log, a stopped one its cause in words with the action that clears it. An analysis that
 * ends done while the page is open opens its Review.
 */
export function AnalysisScreen({ projectId, project, analysis, onChanged, onNavigateStep }: AnalysisScreenProps) {
  const [cancelError, setCancelError] = useState<ApiError | null>(null)
  const queued = analysis.state === "queued"
  const running = analysis.state === "running"
  const live = queued || running
  const events = useJobEvents(analysis.id, live, onChanged)
  const steps = sessionSteps({ project, analysis, current: "analysis", onNavigate: onNavigateStep })
  const pip = project.ecosystem === "pip"
  const files = pip ? "Your requirements files are kept." : "Your package.json is kept."

  // Only an analysis seen running here opens its Review on its own; one that ended before stays readable.
  const sawLive = useRef(live)
  const opened = useRef(false)
  useEffect(() => {
    if (live) sawLive.current = true
    else if (analysis.state === "done" && sawLive.current && !opened.current) {
      opened.current = true
      onNavigateStep("review")
    }
  }, [live, analysis.state, onNavigateStep])

  const restart = useMutation({ mutationFn: () => queueAnalysis(projectId), onSuccess: onChanged })
  const restartError = restart.error instanceof ApiError ? restart.error : null

  async function cancelRun() {
    setCancelError(null)
    try {
      await cancelAnalysis(projectId, analysis.id)
      onChanged()
    } catch (error) {
      setCancelError(error instanceof ApiError ? error : null)
      throw error
    }
  }

  const cancel = (words: Pick<CancelWords, "lost" | "keep">): CancelWords => ({ label: "Cancel", confirm: "Cancel analysis", onConfirm: cancelRun, ...words })

  const ranFor = events.steps.reduce((sum, step) => sum + (step.durationMs ?? 0), 0)
  const kept =
    ranFor > 0 ? (
      <>
        After <span className="figure text-ink">{elapsed(ranFor)}</span>. {files}
      </>
    ) : (
      files
    )

  const replace = (primary: boolean) => (
    <Button asChild size="page" variant={primary ? "default" : "outline"}>
      {pip ? (
        // A pip crossing continues under the project's name, so Update opens titled with it.
        <Link to="/update" search={{ from: project.id }}>
          <FileUp aria-hidden="true" />
          Replace files
        </Link>
      ) : (
        <Link to="/update">
          <FileUp aria-hidden="true" />
          Replace package.json
        </Link>
      )}
    </Button>
  )
  const again = (label: string) => (
    <Button
      type="button"
      size="page"
      aria-busy={restart.isPending ? true : undefined}
      onClick={() => {
        if (!restart.isPending) restart.mutate()
      }}
    >
      {restart.isPending ? <LoaderCircle aria-hidden="true" className="motion-safe:animate-spin" /> : <RotateCcw aria-hidden="true" />}
      {restart.isPending ? "Starting" : label}
    </Button>
  )

  let body: ReactNode
  if (queued) {
    body = <QueuedAnalysis analysis={analysis} cancel={cancel({ lost: `It leaves the queue. ${files}`, keep: "Keep its place" })} />
  } else if (running && pip) {
    // No estimate for pip: the step in words, and the index pages read where the step reads them.
    const step = pipStep(events.steps)
    const pages = step ? events.progressByStep[step] : undefined
    body = (
      <JobProgress
        title={doing(step, true)}
        counted={(step && triedOf(events, step, "index pages read")) || doing(step, true)}
        progress={pages ? { done: pages.done, total: pages.total } : undefined}
        estimating={!pages}
        log={events.log}
        logCount={events.logCount}
        live
        note="Keeps running if you leave this page"
        cancel={cancel({ lost: `The work so far stops here. ${files}`, keep: "Keep running" })}
      />
    )
  } else if (running) {
    const estimate = estimateOf(events)
    const step = currentStep(events.steps)
    const resolve = events.progressByStep["resolve-candidates"]
    const resolveEnded = events.steps.some((s) => s.name === "resolve-candidates")
    body = (
      <JobProgress
        title={timeLeft(estimate) ?? (resolveEnded ? doing(step) : "Estimating time left")}
        counted={triedOf(events, "resolve-candidates", "newer versions tried") ?? doing(step)}
        progress={resolve ? { done: resolve.done, total: resolve.total } : undefined}
        estimating={!resolve}
        log={events.log}
        logCount={events.logCount}
        live
        note="Keeps running if you leave this page"
        cancel={cancel({ lost: "The work so far stops here. Your package.json is kept.", keep: "Keep running" })}
      />
    )
  } else if (analysis.state === "done") {
    body = (
      <>
        <h1 className="text-[28px] font-bold tracking-tight text-ink">Analysis finished</h1>
        <div className="mt-7 flex justify-end">
          <Button type="button" size="page" onClick={() => onNavigateStep("review")}>
            Review
            <ArrowRight aria-hidden="true" />
          </Button>
        </div>
      </>
    )
  } else if (analysis.state === "failed") {
    const cause = analysisCause(analysis, project.ecosystem)
    body = (
      <FailureBlock
        projectId={projectId}
        analysisId={analysis.id}
        heading="Analysis stopped"
        sub={kept}
        cause={cause}
        tone="failure"
        actions={cause.action === "replace" ? replace(true) : again("Retry")}
      />
    )
  } else {
    const cancelled = analysis.state === "cancelled"
    body = (
      <FailureBlock
        projectId={projectId}
        analysisId={analysis.id}
        heading={cancelled ? "Analysis cancelled" : "Analysis interrupted"}
        sub={cancelled ? kept : `The server restarted while it ran. ${files}`}
        tone="neutral"
        actions={
          <>
            {replace(false)}
            {again("Start again")}
          </>
        }
      />
    )
  }

  return (
    <div className="animate-enter mx-auto flex w-full max-w-190 flex-1 flex-col px-5 py-9">
      <StepBar steps={steps} />
      {body}
      {cancelError ? <ProblemNotice status={cancelError.status} problem={cancelError.problem} className="mt-4" /> : null}
      {restartError ? <ProblemNotice status={restartError.status} problem={restartError.problem} className="mt-4" /> : null}
    </div>
  )
}
