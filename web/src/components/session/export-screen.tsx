import { useMutation, useQuery } from "@tanstack/react-query"
import { Link, useNavigate } from "@tanstack/react-router"
import { ArrowLeft, Check, LoaderCircle, RotateCcw } from "lucide-react"
import { useEffect, useId, useState, type ReactNode } from "react"

import { ApiError } from "@/api/client"
import { cancelExport, queueExport, type Analysis, type Export, type Project } from "@/api/projects"
import { EraseProject, useInstance } from "@/components/ephemeral"
import { FailureBlock } from "@/components/failure-block"
import { CancelRow, JobProgress, type CancelWords } from "@/components/job-progress"
import { ProblemNotice } from "@/components/problem-notice"
import { CrossingFiles } from "@/components/projects/crossing-files"
import { hostIn, NO_ANSWER } from "@/components/session/analysis-screen"
import { StepBar, type StepId } from "@/components/step-bar"
import { Button } from "@/components/ui/button"
import { useJobEvents } from "@/hooks/use-job-events"
import { useReasons, useSelection } from "@/hooks/use-selection"
import { timeLeft } from "@/lib/analysisEvents"
import { crossingName, readSeal } from "@/lib/crossings"
import { exportSelection } from "@/lib/exportSelection"
import { reasonsToSend, requiredReasons } from "@/lib/requiredReasons"
import { sessionSteps } from "@/lib/sessionSteps"

interface ExportScreenProps {
  project: Project
  analysis: Analysis
  relatedExport?: Export
  /** The latest done export of this analysis, when a later one did not finish. */
  previousArchive?: Export
  onChanged: () => void
  onNavigateStep: (step: StepId) => void
}

/**
 * The Seal step: a queued export waits for the running job, a running one shows its progress as Analyse
 * does, a stopped one its cause in words with Retry, a cancelled one goes back to Ready to seal, and a done
 * one reads Sealed once its manifest.json reads.
 */
export function ExportScreen({ project, analysis, relatedExport, previousArchive, onChanged, onNavigateStep }: ExportScreenProps) {
  const steps = sessionSteps({ project, analysis, current: "export", onNavigate: onNavigateStep })

  let body: ReactNode
  if (!relatedExport) {
    body = (
      <>
        <h1 className="text-[28px] font-bold tracking-tight text-ink">Nothing sealed yet</h1>
        <div className="mt-7 flex justify-end">
          <Button type="button" variant="outline" size="page" onClick={() => onNavigateStep("review")}>
            <ArrowLeft aria-hidden="true" />
            Back
          </Button>
        </div>
      </>
    )
  } else if (relatedExport.state === "done") {
    body = <Sealed key={relatedExport.id} project={project} analysis={analysis} exported={relatedExport} />
  } else {
    // Keyed by the export's own id, so a retry (a new export, a new id) mounts fresh.
    body = <SealProgress key={relatedExport.id} project={project} analysis={analysis} exportRecord={relatedExport} onChanged={onChanged} onNavigateStep={onNavigateStep} />
  }

  return (
    <div className="animate-enter mx-auto flex w-full max-w-190 flex-1 flex-col px-5 py-9">
      <StepBar steps={steps} />
      {body}
      {previousArchive ? (
        <section className="mt-10">
          <h2 className="text-lg font-semibold text-ink">Earlier archive of this crossing</h2>
          <FilesFrame>
            <CrossingFiles project={project} exported={previousArchive} />
          </FilesFrame>
        </section>
      ) : null}
    </div>
  )
}

// The files block draws a rule above itself for the project page's row; here its frame stands alone.
function FilesFrame({ children }: { children: ReactNode }) {
  return <div className="mt-5 overflow-hidden rounded-xl border border-rule [&>div]:border-t-0">{children}</div>
}

// What each step of internal/jobs' export does while it runs, by the name its step event carries.
const DOING: Record<string, string> = {
  prepare: "Reading the signing key",
  "package-list": "Listing the packages to seal",
  download: "Downloading and verifying each package",
  strip: "Stripping publishConfig",
  archive: "Packing the archive",
  reports: "Signing the manifest and writing the reports",
}

const doing = (step: string | undefined) => (step ? (DOING[step] ?? `Running ${step}`) : "Sealing")
const lower = (words: string) => words.charAt(0).toLowerCase() + words.slice(1)

const COUNT = new Intl.NumberFormat("en-GB")
const figure = (n: number) => <span className="figure text-ink">{COUNT.format(n)}</span>

const KEPT = "Your selection and its reasons are kept."

interface SealProgressProps {
  project: Project
  analysis: Analysis
  exportRecord: Export
  onChanged: () => void
  onNavigateStep: (step: StepId) => void
}

/**
 * A queued, running or stopped export. A failed or interrupted export keeps its status.json on the server,
 * so exportRecord.failure survives a reload; while the stream is open, its failed step event carries the
 * same cause a beat before the next poll refreshes exportRecord.
 */
function SealProgress({ project, analysis, exportRecord, onChanged, onNavigateStep }: SealProgressProps) {
  const selection = useSelection(analysis.id)
  const reasons = useReasons(analysis.id)
  const [cancelError, setCancelError] = useState<ApiError | null>(null)
  const queued = exportRecord.state === "queued"
  const active = queued || exportRecord.state === "running"
  const events = useJobEvents(exportRecord.id, active, onChanged)

  // A cancel is the developer's own stop: the selection and its reasons stay, and Ready to seal comes back.
  const cancelled = exportRecord.state === "cancelled" || (events.ended && events.endState === "cancelled")
  useEffect(() => {
    if (cancelled) onNavigateStep("review")
  }, [cancelled, onNavigateStep])

  const retry = useMutation({
    mutationFn: () => {
      const toExport = exportSelection(analysis.result?.dependencies ?? [], selection.selection)
      const needed = analysis.result ? requiredReasons(analysis.result, toExport) : []
      return queueExport(project.id, analysis.id, { selection: toExport, includeProject: false, reasons: reasonsToSend(needed, reasons.reasons) })
    },
    onSuccess: onChanged,
  })
  const retryError = retry.error instanceof ApiError ? retry.error : null

  async function cancelRun() {
    setCancelError(null)
    try {
      await cancelExport(project.id, exportRecord.id)
      onChanged()
    } catch (error) {
      setCancelError(error instanceof ApiError ? error : null)
      throw error
    }
  }
  const cancel = (words: Pick<CancelWords, "lost" | "keep">): CancelWords => ({ label: "Cancel", confirm: "Cancel sealing", onConfirm: cancelRun, ...words })

  if (cancelled) return null

  const failedStep = events.steps.find((step) => step.state === "failed")
  const failure = exportRecord.failure ?? (failedStep ? { step: failedStep.name, message: failedStep.error ?? "" } : undefined)
  const stopped = exportRecord.state === "failed" || exportRecord.state === "interrupted" || (events.ended && events.endState !== "done")

  const back = (
    <Button type="button" variant="outline" size="page" onClick={() => onNavigateStep("review")}>
      <ArrowLeft aria-hidden="true" />
      Back
    </Button>
  )
  const again = (label: string) => (
    <Button
      type="button"
      size="page"
      aria-busy={retry.isPending ? true : undefined}
      onClick={() => {
        if (!retry.isPending) retry.mutate()
      }}
    >
      {retry.isPending ? <LoaderCircle aria-hidden="true" className="motion-safe:animate-spin" /> : <RotateCcw aria-hidden="true" />}
      {retry.isPending ? "Starting" : label}
    </Button>
  )

  let body: ReactNode
  if (stopped && failure) {
    const message = failure.message?.trim() ?? ""
    // A fetch that got no answer reads by its host; any other cause is the export's own first line.
    const title = NO_ANSWER.test(message) ? `No answer from ${hostIn(message) ?? "the registry"}` : message.split("\n")[0] || "The cause was not recorded"
    body = (
      <FailureBlock
        projectId={project.id}
        analysisId={analysis.id}
        heading="Sealing stopped"
        sub={KEPT}
        cause={{ title, diagnosis: `It stopped while ${lower(doing(failure.step))}.` }}
        tone="failure"
        log={events.log}
        actions={
          <>
            {back}
            {again("Retry")}
          </>
        }
      />
    )
  } else if (stopped) {
    // An interrupted export never failed: the server restarted under it. A failure with no record names no cause.
    const interrupted = exportRecord.state === "interrupted" || events.endState === "interrupted"
    body = (
      <FailureBlock
        projectId={project.id}
        analysisId={analysis.id}
        heading={interrupted ? "Sealing interrupted" : "Sealing stopped"}
        sub={interrupted ? `The server restarted while it ran. ${KEPT}` : `The version that ran it did not record why. ${KEPT}`}
        tone={interrupted ? "neutral" : "failure"}
        log={events.log}
        actions={
          <>
            {back}
            {again(interrupted ? "Start again" : "Retry")}
          </>
        }
      />
    )
  } else if (queued) {
    body = (
      <div>
        <h1 aria-live="polite" className="text-[34px] leading-tight font-bold tracking-tight text-ink">
          Waits for the running job
        </h1>
        <p className="mt-1.5 text-[15px] text-muted">One job runs at a time.</p>
        <CancelRow note="Keeps its place if you leave this page" cancel={cancel({ lost: `It leaves the queue. ${KEPT}`, keep: "Keep its place" })} />
      </div>
    )
  } else {
    // An export reports each step as it starts, so the last one reported and not done is the one running.
    const last = events.steps.at(-1)
    const step = last && last.state !== "done" ? last.name : undefined
    const download = events.progressByStep.download
    // The export sends no estimate today; the title gives the time left only when a progress event carries one.
    const left = download && step === "download" ? timeLeft(download.estimatedRemainingMs) : undefined
    body = (
      <JobProgress
        title={left ?? doing(step)}
        counted={
          download ? (
            <>
              {figure(download.done)} of {figure(download.total)} packages downloaded
            </>
          ) : undefined
        }
        progress={download ? { done: download.done, total: download.total } : undefined}
        estimating={!download}
        log={events.log}
        logCount={events.logCount}
        live
        note="Keeps running if you leave this page"
        cancel={cancel({ lost: `The downloads so far stop here. ${KEPT}`, keep: "Keep sealing" })}
      />
    )
  }

  return (
    <>
      {body}
      {cancelError ? <ProblemNotice status={cancelError.status} problem={cancelError.problem} className="mt-4" /> : null}
      {retryError ? <ProblemNotice status={retryError.status} problem={retryError.problem} className="mt-4" /> : null}
    </>
  )
}

// Kept beside the selection's keys, per export: a reload of the tab keeps Done open, a new tab starts with it disabled.
const startedKey = (exportId: string) => `sealift:download-started:${exportId}`

function readStarted(exportId: string): boolean {
  try {
    return sessionStorage.getItem(startedKey(exportId)) === "true"
  } catch {
    return false
  }
}

/** Whether a download of a file to carry started from this page in this tab, and the call that records one. */
function useDownloadStarted(exportId: string) {
  const [started, setStarted] = useState(() => readStarted(exportId))
  function markStarted() {
    setStarted(true)
    try {
      sessionStorage.setItem(startedKey(exportId), "true")
    } catch {
      // Storage unavailable: Done opens for this page and forgets it on a reload.
    }
  }
  return [started, markStarted] as const
}

/**
 * A done export: Sealed with the crossing's name once manifest.json reads, the erase row on an ephemeral
 * instance, the files to carry and the reports, then Done, which leads Home once a download of a file to
 * carry started.
 */
function Sealed({ project, analysis, exported }: { project: Project; analysis: Analysis; exported: Export }) {
  const navigate = useNavigate()
  const instance = useInstance()
  // The files block reads the same seal under the same key, so the page asks once.
  const seal = useQuery({ queryKey: ["seal", project.id, exported.id], queryFn: () => readSeal(project.id, exported.id), retry: false })
  const [started, markStarted] = useDownloadStarted(exported.id)
  const causeId = useId()
  const name = crossingName(project.name, analysis, project.analyses ?? [analysis])
  const idleMinutes = instance.data?.ephemeral ? instance.data.idleMinutes : undefined

  return (
    <>
      {seal.isSuccess ? (
        <div className="flex items-center gap-4">
          <span className="grid size-11 flex-none place-items-center rounded-full bg-ok text-bg">
            <Check aria-hidden="true" className="size-5" strokeWidth={2.5} />
          </span>
          <div className="min-w-0">
            <h1 className="text-[28px] leading-tight font-bold tracking-tight text-ink">Sealed</h1>
            <p className="text-[15px] text-muted [overflow-wrap:anywhere]">{name}</p>
          </div>
        </div>
      ) : (
        <h1 className="text-[28px] leading-tight font-bold tracking-tight text-ink [overflow-wrap:anywhere]">{name}</h1>
      )}
      {idleMinutes !== undefined ? <EraseProject projectId={project.id} idleMinutes={idleMinutes} onErased={() => void navigate({ to: "/" })} /> : null}
      <FilesFrame>
        <CrossingFiles project={project} exported={exported} downloadAllPrimary onDownload={markStarted} />
      </FilesFrame>
      <div className="mt-7 flex flex-wrap items-center justify-end gap-3">
        {started ? (
          <Button asChild variant="outline" size="page">
            <Link to="/">
              <Check aria-hidden="true" />
              Done
            </Link>
          </Button>
        ) : (
          <>
            <p id={causeId} className="text-[13px] text-muted">
              Opens once a download starts
            </p>
            <Button type="button" variant="outline" size="page" aria-disabled="true" aria-describedby={causeId}>
              <Check aria-hidden="true" />
              Done
            </Button>
          </>
        )}
      </div>
    </>
  )
}
