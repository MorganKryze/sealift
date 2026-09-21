import { useEffect, useState } from "react"

import { cancelExport } from "@/api/projects"
import { Mark } from "@/components/brand/Mark"
import { Button } from "@/components/ui/button"
import { useJobEvents } from "@/hooks/use-job-events"
import { formatDuration } from "@/lib/utils"

interface ExportRunningProps {
  projectId: string
  exportId: string
  onEnd: () => void
}

export function ExportRunning({ projectId, exportId, onEnd }: ExportRunningProps) {
  const [logOpen, setLogOpen] = useState(false)
  const [cancelling, setCancelling] = useState(false)
  // The parent only learns the export failed after a refetch, at which
  // point the terminal Export carries no per-step detail (unlike Analysis,
  // it has no warnings field either): the failed step is only ever visible
  // here, while the stream that reported it is still open. So a failed run
  // holds this view, with the step named, until the user moves on.
  const events = useJobEvents(exportId, true, () => {})

  useEffect(() => {
    if (events.ended && events.endState === "done") {
      onEnd()
    }
  }, [events.ended, events.endState, onEnd])

  async function handleCancel() {
    if (!window.confirm("Cancel this export?")) {
      return
    }
    setCancelling(true)
    try {
      await cancelExport(projectId, exportId)
    } finally {
      setCancelling(false)
    }
  }

  const progressPercent =
    events.progress && events.progress.total > 0
      ? Math.round((events.progress.done / events.progress.total) * 100)
      : null
  const stoppedAt = events.ended ? events.steps.find((step) => step.state === "failed") : undefined

  return (
    <div className="flex flex-col gap-6 p-8">
      <div className="flex items-center gap-4">
        <Mark size={40} className={events.ended ? undefined : "animate-mark-lift"} />
        <div>
          <h2 className="text-lg font-semibold text-ink">
            {events.ended && events.endState !== "done" ? `Export ${events.endState}` : "Export running"}
          </h2>
          <p className="text-sm text-muted">
            {events.ended && events.endState !== "done"
              ? stoppedAt
                ? `Stopped at ${stoppedAt.name}.`
                : "Stopped."
              : events.progress?.estimatedRemainingMs !== undefined
                ? `About ${formatDuration(events.progress.estimatedRemainingMs)} remaining`
                : "Working…"}
          </p>
        </div>
        {events.ended && events.endState !== "done" ? (
          <Button className="ml-auto" onClick={onEnd}>
            Back to export
          </Button>
        ) : (
          <Button variant="outline" className="ml-auto" onClick={() => void handleCancel()} disabled={cancelling}>
            Cancel
          </Button>
        )}
      </div>

      {progressPercent !== null ? (
        <div
          role="progressbar"
          aria-valuenow={progressPercent}
          aria-valuemin={0}
          aria-valuemax={100}
          className="h-2 w-full overflow-hidden rounded-full bg-card"
        >
          <div className="h-full bg-accent transition-[width]" style={{ width: `${progressPercent}%` }} />
        </div>
      ) : null}

      {events.progress?.cacheHits !== undefined ? (
        <p className="text-xs text-muted">{events.progress.cacheHits} from cache</p>
      ) : null}

      <ol className="flex flex-col gap-2">
        {events.steps.map((step) => (
          <li
            key={step.name}
            className="flex items-center justify-between rounded-md border border-line px-4 py-2 text-sm"
          >
            <span className="text-ink">{step.name}</span>
            <span className="text-muted">
              {step.state}
              {step.durationMs !== undefined ? ` · ${formatDuration(step.durationMs)}` : ""}
            </span>
          </li>
        ))}
      </ol>

      <div>
        <button
          type="button"
          onClick={() => setLogOpen((open) => !open)}
          aria-expanded={logOpen}
          className="text-sm font-medium text-accent"
        >
          {logOpen ? "Hide log" : "Show log"}
        </button>
        {logOpen ? (
          <pre className="mt-2 max-h-64 overflow-auto rounded-md bg-card p-3 text-xs text-muted">
            {events.logLines.join("\n")}
          </pre>
        ) : null}
      </div>
    </div>
  )
}
