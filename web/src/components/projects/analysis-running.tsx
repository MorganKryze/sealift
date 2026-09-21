import { useQueryClient } from "@tanstack/react-query"
import { useState } from "react"

import { cancelAnalysis } from "@/api/projects"
import { Mark } from "@/components/brand/Mark"
import { Button } from "@/components/ui/button"
import { useJobEvents } from "@/hooks/use-job-events"
import { formatDuration } from "@/lib/utils"

interface AnalysisRunningProps {
  projectId: string
  analysisId: string
}

export function AnalysisRunning({ projectId, analysisId }: AnalysisRunningProps) {
  const queryClient = useQueryClient()
  const [cancelling, setCancelling] = useState(false)
  const [logOpen, setLogOpen] = useState(false)

  const events = useJobEvents(analysisId, true, () => {
    void queryClient.invalidateQueries({ queryKey: ["project", projectId] })
  })

  async function handleCancel() {
    if (!window.confirm("Cancel this analysis?")) {
      return
    }
    setCancelling(true)
    try {
      await cancelAnalysis(projectId, analysisId)
    } finally {
      setCancelling(false)
    }
  }

  const progressPercent =
    events.progress && events.progress.total > 0
      ? Math.round((events.progress.done / events.progress.total) * 100)
      : null

  return (
    <div className="flex flex-col gap-6 p-8">
      <div className="flex items-center gap-4">
        <Mark size={40} className="animate-mark-lift" />
        <div>
          <h2 className="text-lg font-semibold text-ink">Analysis running</h2>
          <p className="text-sm text-muted">
            {events.progress?.estimatedRemainingMs !== undefined
              ? `About ${formatDuration(events.progress.estimatedRemainingMs)} remaining`
              : "Working…"}
          </p>
        </div>
        <Button variant="outline" className="ml-auto" onClick={() => void handleCancel()} disabled={cancelling}>
          Cancel
        </Button>
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

      {events.candidates.length > 0 ? (
        <div className="flex flex-col gap-2">
          <h3 className="text-sm font-medium text-ink">Candidates found</h3>
          <ul className="flex flex-col gap-1 text-sm text-muted">
            {events.candidates.map((candidate, index) => (
              <li key={`${candidate.dependency}-${candidate.version}-${index}`}>
                {candidate.dependency} → {candidate.version}
              </li>
            ))}
          </ul>
        </div>
      ) : null}

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
