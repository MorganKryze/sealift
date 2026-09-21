import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"

import { ProblemError } from "@/api/client"
import { activateTrivy, getTools, updateTrivy, updateTrivyDB, type ToolsState } from "@/api/settings"
import { ProblemNotice } from "@/components/problem-notice"
import { Button } from "@/components/ui/button"

interface ToolsPanelProps {
  minReleaseAgeDays: number
}

export function ToolsPanel({ minReleaseAgeDays }: ToolsPanelProps) {
  const queryClient = useQueryClient()
  const toolsQuery = useQuery({ queryKey: ["tools"], queryFn: getTools })

  function onChanged(state: ToolsState) {
    queryClient.setQueryData(["tools"], state)
  }

  const updateMutation = useMutation({ mutationFn: (force: boolean) => updateTrivy(force), onSuccess: onChanged })
  const activateMutation = useMutation({ mutationFn: activateTrivy, onSuccess: onChanged })
  const dbMutation = useMutation({ mutationFn: updateTrivyDB, onSuccess: onChanged })

  if (toolsQuery.isPending) {
    return <p className="text-muted">Loading tools…</p>
  }

  if (toolsQuery.isError) {
    return (
      <p role="alert" className="text-sm text-severity-critical">
        Could not load the tools state.
      </p>
    )
  }

  const tools = toolsQuery.data
  const updateError = updateMutation.error instanceof ProblemError ? updateMutation.error : null

  function installAnyway() {
    const confirmed = window.confirm(
      `The latest Trivy release came out ${tools.trivyLatestAge} ago. Releases wait at least ` +
        `${minReleaseAgeDays} day(s) before installing automatically, to avoid shipping a just-published, ` +
        "unvetted build. Install it now anyway?",
    )
    if (confirmed) {
      updateMutation.mutate(true)
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <h2 className="text-lg font-semibold text-ink">Tools</h2>

      <div className="flex flex-col gap-2">
        <p className="text-sm text-ink">
          Active Trivy: <span className="font-medium">{tools.trivyActive}</span>
        </p>
        <p className="text-sm text-muted">
          Latest release {tools.trivyLatest} · {tools.trivyLatestAge} ago
        </p>

        <ul className="flex flex-col gap-1">
          {tools.trivyInstalled.map((version) => (
            <li key={version} className="flex items-center justify-between rounded-md border border-line p-2 text-sm">
              <span className={version === tools.trivyActive ? "font-medium text-ink" : "text-ink"}>{version}</span>
              <Button
                variant="outline"
                size="sm"
                disabled={version === tools.trivyActive || activateMutation.isPending}
                onClick={() => activateMutation.mutate(version)}
              >
                Activate
              </Button>
            </li>
          ))}
        </ul>

        {updateError ? (
          <ProblemNotice status={updateError.status} problem={updateError.problem}>
            <Button variant="outline" size="sm" className="mt-2" onClick={installAnyway}>
              Install anyway
            </Button>
          </ProblemNotice>
        ) : null}

        <Button
          variant="outline"
          className="self-start"
          disabled={updateMutation.isPending}
          onClick={() => updateMutation.mutate(false)}
        >
          Update Trivy
        </Button>
      </div>

      <div className="flex flex-col gap-2">
        <p className="text-sm text-ink">Vulnerability database: {new Date(tools.trivyDbDate).toLocaleString()}</p>
        <Button variant="outline" className="self-start" disabled={dbMutation.isPending} onClick={() => dbMutation.mutate()}>
          Update database
        </Button>
        {dbMutation.error instanceof ProblemError ? (
          <ProblemNotice status={dbMutation.error.status} problem={dbMutation.error.problem} />
        ) : null}
      </div>

      <div className="flex flex-col gap-2">
        <p className="text-sm text-ink">Installed pnpm versions</p>
        <ul className="flex flex-col gap-1 text-sm text-muted">
          {tools.pnpmInstalled.map((version) => (
            <li key={version}>{version}</li>
          ))}
        </ul>
      </div>
    </div>
  )
}
