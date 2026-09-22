import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { LoaderCircle } from "lucide-react"

import { ProblemError } from "@/api/client"
import { activateTrivy, getTools, updateTrivy, updateTrivyDB, type ToolsState } from "@/api/settings"
import { ProblemNotice } from "@/components/problem-notice"
import { Button } from "@/components/ui/button"
import { formatDbDate, formatGoDuration } from "@/lib/format-tools"

interface ToolsPanelProps {
  minReleaseAgeDays: number
}

export function ToolsPanel({ minReleaseAgeDays }: ToolsPanelProps) {
  const queryClient = useQueryClient()
  const toolsQuery = useQuery({ queryKey: ["tools"], queryFn: getTools })

  function onChanged(state: ToolsState) {
    queryClient.setQueryData(["tools"], state)
  }

  // Keeps the version active before the click, so the result can say whether anything changed.
  const updateMutation = useMutation({
    mutationFn: async (force: boolean) => ({ before: toolsQuery.data?.trivyActive, state: await updateTrivy(force) }),
    onSuccess: ({ state }) => onChanged(state),
  })
  const activateMutation = useMutation({ mutationFn: activateTrivy, onSuccess: onChanged })
  const dbMutation = useMutation({ mutationFn: updateTrivyDB, onSuccess: onChanged })

  if (toolsQuery.isPending) {
    return <p className="text-muted">Loading tools…</p>
  }

  if (toolsQuery.isError) {
    return (
      <p role="alert" className="text-sm text-severity-critical-fg">
        Could not load the tools state.
      </p>
    )
  }

  const tools = toolsQuery.data
  const updateError = updateMutation.error instanceof ProblemError ? updateMutation.error : null
  const activateError = activateMutation.error instanceof ProblemError ? activateMutation.error : null
  const dbError = dbMutation.error instanceof ProblemError ? dbMutation.error : null

  function installAnyway() {
    const confirmed = window.confirm(
      `The latest Trivy release came out ${formatGoDuration(tools.trivyLatestAge)} ago. Releases wait at least ` +
        `${minReleaseAgeDays} day(s) before installing automatically, to avoid shipping a just-published, ` +
        "unvetted build. Install it now anyway?",
    )
    if (confirmed) {
      updateMutation.mutate(true)
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <h2 className="text-base font-semibold text-ink">Scanner</h2>

      <div className="flex flex-col gap-2">
        <p className="text-sm text-ink">
          Active Trivy: <span className="font-medium">{tools.trivyActive || "none installed"}</span>
        </p>
        <p className="text-sm text-muted">
          Latest release {tools.trivyLatest} · {formatGoDuration(tools.trivyLatestAge)} ago
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

        {activateError ? <ProblemNotice status={activateError.status} problem={activateError.problem} /> : null}

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
          {updateMutation.isPending ? (
            <>
              <LoaderCircle className="size-4 animate-spin" /> Checking for a newer Trivy…
            </>
          ) : (
            "Update Trivy"
          )}
        </Button>
        {updateMutation.isSuccess ? (
          <p role="status" className="text-sm text-severity-resolved-fg">
            {updateMutation.data.state.trivyActive === updateMutation.data.before
              ? `Trivy ${updateMutation.data.state.trivyActive} is already the newest release sealift installs.`
              : `Trivy ${updateMutation.data.state.trivyActive} installed and active.`}
          </p>
        ) : null}
      </div>

      <div className="flex flex-col gap-2">
        <p className="text-sm text-ink">Vulnerability database: {formatDbDate(tools.trivyDbDate)}</p>
        <Button variant="outline" className="self-start" disabled={dbMutation.isPending} onClick={() => dbMutation.mutate()}>
          {dbMutation.isPending ? (
            <>
              <LoaderCircle className="size-4 animate-spin" /> Updating the database…
            </>
          ) : (
            "Update database"
          )}
        </Button>
        {dbMutation.isSuccess ? (
          <p role="status" className="text-sm text-severity-resolved-fg">
            Database updated: {formatDbDate(dbMutation.data.trivyDbDate)}.
          </p>
        ) : null}
        {dbError ? <ProblemNotice status={dbError.status} problem={dbError.problem} /> : null}
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
