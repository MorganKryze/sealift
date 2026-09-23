import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { LoaderCircle } from "lucide-react"

import { ProblemError } from "@/api/client"
import { activateTrivy, getTools, updateTrivy, updateTrivyDB, type ToolsState } from "@/api/settings"
import { ProblemNotice } from "@/components/problem-notice"
import { Button } from "@/components/ui/button"
import { formatDbDate, formatGoDuration } from "@/lib/format-tools"

interface ToolsPanelProps {
  minReleaseAgeDays: number
  /** The pnpm version the server resolves with; read-only, since the binary is chosen at startup. */
  pnpmVersion: string
}

export function ToolsPanel({ minReleaseAgeDays, pnpmVersion }: ToolsPanelProps) {
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
  const dbMutation = useMutation({
    mutationFn: async () => ({ before: toolsQuery.data?.trivyDbDate, state: await updateTrivyDB() }),
    onSuccess: ({ state }) => onChanged(state),
  })

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

  const card = "flex flex-col gap-3 rounded-lg border border-line bg-card p-4"
  const otherVersions = tools.trivyInstalled.filter((version) => version !== tools.trivyActive)

  return (
    <section className="flex flex-col gap-4">
      <div>
        <h2 className="text-base font-semibold text-ink">Scanner</h2>
        <p className="mt-0.5 text-sm text-muted">Trivy, its vulnerability database, and the pnpm every project resolves with.</p>
      </div>

      <div className={card}>
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <p className="text-sm font-medium text-ink">
              Trivy <span className="font-mono">{tools.trivyActive || "not installed"}</span>
            </p>
            <p className="mt-0.5 text-xs text-muted">
              {tools.trivyLatest
                ? `Latest release ${tools.trivyLatest}, ${formatGoDuration(tools.trivyLatestAge)} ago`
                : "Latest release unknown: sealift could not reach GitHub."}
            </p>
          </div>
          <Button variant="outline" size="sm" className="shrink-0" disabled={updateMutation.isPending} onClick={() => updateMutation.mutate(false)}>
            {updateMutation.isPending ? (
              <>
                <LoaderCircle className="size-4 animate-spin" /> Checking for a newer Trivy…
              </>
            ) : (
              "Update Trivy"
            )}
          </Button>
        </div>
        {updateMutation.isSuccess ? (
          <p role="status" className="text-sm text-severity-resolved-fg">
            {updateMutation.data.state.trivyActive === updateMutation.data.before
              ? `Trivy ${updateMutation.data.state.trivyActive} is already the newest release sealift installs.`
              : `Trivy ${updateMutation.data.state.trivyActive} installed and active.`}
          </p>
        ) : null}
        {updateError ? (
          <ProblemNotice status={updateError.status} problem={updateError.problem}>
            {/* A 409 means the latest release is younger than the minimum age; only then does forcing it help. */}
            {updateError.status === 409 ? (
              <Button variant="outline" size="sm" className="mt-2" onClick={installAnyway}>
                Install anyway
              </Button>
            ) : null}
          </ProblemNotice>
        ) : null}
        {otherVersions.length > 0 ? (
          <div className="border-t border-line pt-3">
            <p className="text-xs text-muted">Also installed, to roll back to:</p>
            <ul className="mt-2 flex flex-col gap-1.5">
              {otherVersions.map((version) => (
                <li key={version} className="flex items-center justify-between gap-3 text-sm">
                  <span className="font-mono text-ink">{version}</span>
                  <Button variant="ghost" size="sm" disabled={activateMutation.isPending} onClick={() => activateMutation.mutate(version)}>
                    Use this version
                  </Button>
                </li>
              ))}
            </ul>
          </div>
        ) : null}
        {activateError ? <ProblemNotice status={activateError.status} problem={activateError.problem} /> : null}
      </div>

      <div className={card}>
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <p className="text-sm font-medium text-ink">Vulnerability database</p>
            <p className="mt-0.5 text-xs text-muted">Downloaded {formatDbDate(tools.trivyDbDate)}. sealift refreshes it before each analysis.</p>
          </div>
          <Button variant="outline" size="sm" className="shrink-0" disabled={dbMutation.isPending} onClick={() => dbMutation.mutate()}>
            {dbMutation.isPending ? (
              <>
                <LoaderCircle className="size-4 animate-spin" /> Updating the database…
              </>
            ) : (
              "Update database"
            )}
          </Button>
        </div>
        {dbMutation.isSuccess ? (
          <p role="status" className="text-sm text-severity-resolved-fg">
            {dbMutation.data.state.trivyDbDate === dbMutation.data.before
              ? `The database is already current, downloaded ${formatDbDate(dbMutation.data.state.trivyDbDate)}.`
              : `Database updated: ${formatDbDate(dbMutation.data.state.trivyDbDate)}.`}
          </p>
        ) : null}
        {dbError ? <ProblemNotice status={dbError.status} problem={dbError.problem} /> : null}
      </div>

      <div className={card}>
        <div>
          <p className="text-sm font-medium text-ink">
            pnpm <span className="font-mono">{pnpmVersion}</span>
          </p>
          <p className="mt-0.5 text-xs text-muted">Resolves every project. sealift picks it when it starts.</p>
        </div>
      </div>
    </section>
  )
}
