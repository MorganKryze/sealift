import { useMutation } from "@tanstack/react-query"
import { Link } from "@tanstack/react-router"
import { useState } from "react"

import { queueExport, type Export } from "@/api/projects"
import { ProblemError } from "@/api/client"
import { ProblemNotice } from "@/components/problem-notice"
import { Button } from "@/components/ui/button"
import { useSelection } from "@/hooks/use-selection"

interface ExportLaunchProps {
  projectId: string
  analysisId: string
  analysisCreatedAt: string
  previousState?: Export["state"]
  onQueued: () => void
}

const STALE_ANALYSIS_DAYS = 7
const MS_PER_DAY = 24 * 60 * 60 * 1000

export function ExportLaunch({ projectId, analysisId, analysisCreatedAt, previousState, onQueued }: ExportLaunchProps) {
  const selection = useSelection(analysisId)
  const [includeProject, setIncludeProject] = useState(false)
  const [now] = useState(() => Date.now())

  const grouped = Object.entries(selection.selection).filter(([, versions]) => versions.length > 0)
  const hasSelection = grouped.length > 0
  const ageDays = (now - new Date(analysisCreatedAt).getTime()) / MS_PER_DAY

  const launchMutation = useMutation({
    mutationFn: () =>
      queueExport(projectId, analysisId, {
        selection: Object.fromEntries(grouped),
        includeProject,
      }),
    onSuccess: onQueued,
  })

  const launchError = launchMutation.error instanceof ProblemError ? launchMutation.error : null

  return (
    <div className="flex flex-col gap-6 p-8">
      {previousState ? <p className="text-sm text-muted">The previous export {previousState}.</p> : null}

      <div className="flex flex-col gap-3">
        <h2 className="text-lg font-semibold text-ink">Selected versions</h2>
        {hasSelection ? (
          <ul className="flex flex-col gap-2">
            {grouped.map(([dependency, versions]) => (
              <li key={dependency} className="rounded-md border border-line p-3 text-sm">
                <span className="font-medium text-ink">{dependency}</span>
                <span className="ml-2 text-muted">{versions.join(", ")}</span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-muted">Nothing selected yet.</p>
        )}
      </div>

      <label className="flex items-center gap-2 text-sm text-ink">
        <input
          type="checkbox"
          checked={includeProject}
          onChange={(event) => setIncludeProject(event.target.checked)}
        />
        Include the current project tree
      </label>

      {ageDays > STALE_ANALYSIS_DAYS ? (
        <p className="rounded-md border border-severity-medium/40 bg-severity-medium/5 p-3 text-sm text-ink">
          This analysis is more than {STALE_ANALYSIS_DAYS} days old. Consider running a new one before exporting.
        </p>
      ) : null}

      {launchError ? (
        <ProblemNotice status={launchError.status} problem={launchError.problem}>
          <Link to="/settings" className="mt-2 inline-block text-accent underline">
            Go to Settings
          </Link>
        </ProblemNotice>
      ) : null}

      <Button
        className="self-start"
        disabled={(!hasSelection && !includeProject) || launchMutation.isPending}
        onClick={() => launchMutation.mutate()}
      >
        Launch export
      </Button>
    </div>
  )
}
