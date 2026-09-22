import { useMutation, useQuery } from "@tanstack/react-query"
import { Link, useNavigate } from "@tanstack/react-router"
import { useState } from "react"

import { apiFetch, ApiError } from "@/api/client"
import { cancelExport, queueExport, type Analysis, type Export, type Project } from "@/api/projects"
import { Mark } from "@/components/brand/Mark"
import { ProblemNotice } from "@/components/problem-notice"
import { StepBar, type StepId } from "@/components/step-bar"
import { Button } from "@/components/ui/button"
import { Card } from "@/components/ui/card"
import { Progress } from "@/components/ui/progress"
import { useJobEvents } from "@/hooks/use-job-events"
import { useSelection } from "@/hooks/use-selection"
import { sessionSteps, TERMINAL_FAILED_STATES } from "@/lib/sessionSteps"
import { cn, formatBytes, formatDuration } from "@/lib/utils"

interface ExportScreenProps {
  project: Project
  analysis: Analysis
  relatedExport?: Export
  /** The latest done export of this analysis, when a later one did not finish. */
  previousArchive?: Export
  onChanged: () => void
  onNavigateStep: (step: StepId) => void
}

export function ExportScreen({ project, analysis, relatedExport, previousArchive, onChanged, onNavigateStep }: ExportScreenProps) {
  const navigate = useNavigate()
  const steps = sessionSteps({ project, current: "export", onNavigate: onNavigateStep })

  return (
    <div className="animate-enter mx-auto flex w-full max-w-240 flex-1 flex-col px-5 py-8">
      <StepBar steps={steps} />

      {!relatedExport ? (
        <div className="flex flex-col items-start gap-3 p-8">
          <p className="text-muted">Nothing exported yet for this analysis.</p>
          <Button asChild>
            <Link to="/sessions/$sessionId/review" params={{ sessionId: project.id }}>
              Go to Review
            </Link>
          </Button>
        </div>
      ) : relatedExport.state === "done" ? (
        <ArchiveDone
          projectId={project.id}
          exportId={relatedExport.id}
          files={relatedExport.files ?? []}
          onExportAnother={() => void navigate({ to: "/sessions/$sessionId/review", params: { sessionId: project.id } })}
          onNewSession={() => void navigate({ to: "/" })}
        />
      ) : (
        <ExportProgress
          key={relatedExport.id}
          projectId={project.id}
          analysisId={analysis.id}
          exportRecord={relatedExport}
          onChanged={onChanged}
        />
      )}

      {previousArchive ? (
        <section className="mt-10 border-t border-line pt-8">
          <h2 className="mb-4 text-lg font-semibold text-ink">Earlier archive from this analysis</h2>
          <ArchiveDone
            projectId={project.id}
            exportId={previousArchive.id}
            files={previousArchive.files ?? []}
            onExportAnother={() => void navigate({ to: "/sessions/$sessionId/review", params: { sessionId: project.id } })}
            onNewSession={() => void navigate({ to: "/" })}
          />
        </section>
      ) : null}
    </div>
  )
}

interface ExportProgressProps {
  projectId: string
  analysisId: string
  exportRecord: Export
  onChanged: () => void
}

/**
 * Covers queued, running and every terminal-but-failed state in one
 * component, keyed by the export's own id so a retry (a new export, a new
 * id) mounts fresh. A failed or cancelled export keeps its status.json on
 * the server (see internal/jobs.Export.Run), so exportRecord.failure
 * survives a reload; while the live stream is still open, events.steps
 * carries the same cause a beat earlier, before the next poll refreshes
 * exportRecord itself.
 */
function ExportProgress({ projectId, analysisId, exportRecord, onChanged }: ExportProgressProps) {
  const selection = useSelection(analysisId)
  const [cancelling, setCancelling] = useState(false)
  const [cancelError, setCancelError] = useState<ApiError | null>(null)
  const active = exportRecord.state === "queued" || exportRecord.state === "running"
  const events = useJobEvents(exportRecord.id, active, onChanged)

  const retryMutation = useMutation({
    mutationFn: () => queueExport(projectId, analysisId, { selection: selection.selection, includeProject: false }),
    onSuccess: onChanged,
  })
  const retryError = retryMutation.error instanceof ApiError ? retryMutation.error : null

  async function handleCancel() {
    if (!window.confirm("Cancel this export?")) {
      return
    }
    setCancelling(true)
    setCancelError(null)
    try {
      await cancelExport(projectId, exportRecord.id)
      onChanged()
    } catch (error) {
      setCancelError(error instanceof ApiError ? error : null)
    } finally {
      setCancelling(false)
    }
  }

  // A page opened directly on an already-terminal export never had a live
  // stream: everything shown then comes from exportRecord itself, which a
  // failed or cancelled export's status.json fills in (see
  // internal/store.readExportInfo).
  const cold = !active && !events.ended
  const failed = cold ? TERMINAL_FAILED_STATES.has(exportRecord.state) : events.ended && events.endState !== "done"
  const stoppedAt = events.ended ? events.steps.find((step) => step.state === "failed") : undefined
  // A cancel stops the download with a "context canceled" error; the user
  // asked for that stop, so it reads as their action, not as a failure.
  const cancelled = (cold ? exportRecord.state : events.endState) === "cancelled"
  const failureMessage = cancelled ? "You cancelled this export." : (exportRecord.failure?.message ?? stoppedAt?.error)
  const progressPercent =
    events.progress && events.progress.total > 0 ? Math.round((events.progress.done / events.progress.total) * 100) : null

  const title = failed ? (cancelled ? "Export cancelled" : "Export failed") : "Building the archive"

  return (
    <>
      <div className="mb-6">
        <h1 className="text-2xl font-bold tracking-tight text-ink">{title}</h1>
        <p className="mt-1.5 max-w-[62ch] text-muted">
          {failed
            ? (failureMessage ?? (stoppedAt ? `Stopped at ${stoppedAt.name}.` : "Stopped. The next action is below."))
            : events.progress?.estimatedRemainingMs !== undefined
              ? `Downloading each package from the registry, checking its integrity, then packing. About ${formatDuration(events.progress.estimatedRemainingMs)} remaining.`
              : "Downloading each package from the registry, checking its integrity, then packing."}
        </p>
      </div>

      {!failed ? (
        <>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
            <Card className="p-4">
              <p className="text-xs text-muted">Packages</p>
              <p className="text-xl font-bold tracking-tight text-ink tabular-nums">
                {events.progress?.done ?? 0}
                <span className="ml-1 text-sm font-medium text-muted">/ {events.progress?.total ?? "…"}</span>
              </p>
            </Card>
            <Card className="p-4">
              <p className="text-xs text-muted">From cache</p>
              <p className="text-xl font-bold tracking-tight text-ink tabular-nums">{events.progress?.cacheHits ?? 0}</p>
            </Card>
          </div>
          {progressPercent !== null ? <Progress className="mt-3" value={progressPercent} label="Export progress" /> : null}
        </>
      ) : null}

      {events.steps.length > 0 ? (
        <Card className="mt-5">
          <ol>
            {events.steps.map((step, index) => (
              <li
                key={step.name}
                className={cn("flex items-center justify-between px-4.5 py-2.5 text-sm", index > 0 && "border-t border-line")}
              >
                <span className={step.state === "failed" ? "text-severity-critical-fg" : "text-ink"}>{step.name}</span>
                <span className="font-mono text-xs text-muted">
                  {step.state}
                  {step.durationMs !== undefined ? ` · ${formatDuration(step.durationMs)}` : ""}
                </span>
              </li>
            ))}
          </ol>
        </Card>
      ) : null}

      {!failed && active ? (
        <div className="mt-5 flex flex-col items-start gap-2">
          <Button variant="outline" onClick={() => void handleCancel()} disabled={cancelling}>
            Cancel
          </Button>
          {cancelError ? <ProblemNotice status={cancelError.status} problem={cancelError.problem} /> : null}
        </div>
      ) : null}

      {failed ? (
        <div className="mt-5 flex flex-col items-start gap-2">
          <div className="flex flex-wrap gap-3">
            <Button onClick={() => retryMutation.mutate()} disabled={retryMutation.isPending}>
              {retryMutation.isPending ? "Starting…" : "Retry"}
            </Button>
            <Button variant="ghost" asChild>
              <Link to="/sessions/$sessionId/review" params={{ sessionId: projectId }}>
                Choose different versions
              </Link>
            </Button>
          </div>
          {retryError ? <ProblemNotice status={retryError.status} problem={retryError.problem} /> : null}
        </div>
      ) : null}
    </>
  )
}

const REPORT_DESCRIPTIONS: Record<string, string> = {
  "summary.md": "Readable summary: before, after, remaining CVEs",
  "findings.csv": "Every CVE, one row each",
  "manifest.json": "Every package with its sha512",
  "report.cdx.json": "CycloneDX SBOM",
  "report.trivy.json": "Raw Trivy output",
}

// manifest.json's shape is not part of the OpenAPI schema (the download
// route types every file as an opaque octet-stream); this mirrors
// internal/report.Manifest, the job's own writer.
interface ExportManifest {
  archive: {
    sha256: string
    size: number
  }
  packages: unknown[]
}

interface ArchiveDoneProps {
  projectId: string
  exportId: string
  files: string[]
  onExportAnother: () => void
  onNewSession: () => void
}

function ArchiveDone({ projectId, exportId, files, onExportAnother, onNewSession }: ArchiveDoneProps) {
  const manifestQuery = useQuery({
    queryKey: ["export-manifest", projectId, exportId],
    queryFn: () => apiFetch<ExportManifest>(`/projects/${projectId}/exports/${exportId}/files/manifest.json`),
  })
  const [copied, setCopied] = useState(false)
  const archiveFile = files.find((name) => name === "packages_npm.tar.gz")
  const reportFiles = files.filter((name) => name !== archiveFile)

  async function copyHash() {
    if (!manifestQuery.data) {
      return
    }
    try {
      await navigator.clipboard.writeText(manifestQuery.data.archive.sha256)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      // Clipboard API unavailable (permissions, insecure context): the
      // hash is still there to select and copy by hand.
    }
  }

  return (
    <>
      <div className="mb-6">
        <h1 className="text-2xl font-bold tracking-tight text-ink">Archive ready</h1>
        <p className="mt-1.5 max-w-[62ch] text-muted">
          Carry this file through the kiosk. The reports travel with it for whoever imports it.
        </p>
      </div>

      <Card className="grid grid-cols-[auto_1fr] items-center gap-5 p-6">
        <Mark size={72} className="animate-stamp" />
        <div>
          {manifestQuery.isPending ? (
            <p className="text-sm text-muted">Reading the manifest…</p>
          ) : manifestQuery.isError ? (
            <p className="text-sm text-severity-critical-fg">Could not read manifest.json.</p>
          ) : (
            <>
              <p className="text-xs uppercase tracking-wide text-muted">
                Sealed · {manifestQuery.data.packages.length} packages · {formatBytes(manifestQuery.data.archive.size)}
              </p>
              <h2 className="mt-1 font-mono text-lg font-semibold text-ink">packages_npm.tar.gz</h2>
              <div className="mt-2.5 flex flex-wrap items-center gap-2">
                <code className="flex-1 break-all rounded-lg border border-line bg-card px-2.5 py-1.5 font-mono text-xs">
                  sha256 {manifestQuery.data.archive.sha256}
                </code>
                <Button variant="outline" size="sm" onClick={() => void copyHash()}>
                  {copied ? "Copied" : "Copy"}
                </Button>
              </div>
              {archiveFile ? (
                <div className="mt-3.5">
                  <Button size="lg" asChild>
                    <a href={`/api/projects/${projectId}/exports/${exportId}/files/${encodeURIComponent(archiveFile)}`} download>
                      Download archive
                    </a>
                  </Button>
                </div>
              ) : null}
            </>
          )}
        </div>
      </Card>

      {reportFiles.length > 0 ? (
        <section className="mt-7">
          <div className="mb-2.5 flex items-baseline gap-2.5">
            <h2 className="text-lg font-semibold text-ink">Reports</h2>
            <span className="text-sm text-muted">{reportFiles.length} files, included in the archive&rsquo;s folder</span>
          </div>
          <Card>
            {reportFiles.map((name, index) => (
              <div
                key={name}
                className={cn("flex items-center justify-between gap-3 px-4.5 py-3", index > 0 && "border-t border-line")}
              >
                <span>
                  <span className="font-mono text-sm text-ink">{name}</span>
                  <p className="text-xs text-muted">{REPORT_DESCRIPTIONS[name] ?? ""}</p>
                </span>
                <Button variant="outline" size="sm" asChild>
                  <a href={`/api/projects/${projectId}/exports/${exportId}/files/${encodeURIComponent(name)}`} download>
                    Download
                  </a>
                </Button>
              </div>
            ))}
          </Card>
        </section>
      ) : null}

      <div className="mt-6 flex flex-wrap gap-3">
        <Button variant="outline" onClick={onExportAnother}>
          Export another selection
        </Button>
        <Button variant="ghost" onClick={onNewSession}>
          Start a new session
        </Button>
      </div>
    </>
  )
}
