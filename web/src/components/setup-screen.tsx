import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Check, Database, KeyRound, LoaderCircle, ShieldCheck } from "lucide-react"
import { useState, type ReactNode } from "react"

import { ProblemError } from "@/api/client"
import { getSettings, updateSettings, updateTrivy, updateTrivyDB, type ToolsState } from "@/api/settings"
import { ProblemNotice } from "@/components/problem-notice"
import { Button } from "@/components/ui/button"
import { Card } from "@/components/ui/card"
import { formatDbDate, formatGoDuration } from "@/lib/format-tools"
import { formatBytes } from "@/lib/utils"

interface SetupScreenProps {
  tools: ToolsState
  /** Leaves setup once every tool is ready; setup never leaves on its own, so the ready state stays visible. */
  onContinue: () => void
}

/**
 * First-run gate: shown at "/" whenever GET /tools reports ready: false.
 * Nothing here installs on mount: every download starts from a click, so
 * nothing lands on the machine until the user asks for it.
 */
export function SetupScreen({ tools, onContinue }: SetupScreenProps) {
  const queryClient = useQueryClient()
  const settingsQuery = useQuery({ queryKey: ["settings"], queryFn: getSettings })
  const [keyValue, setKeyValue] = useState("")

  const installMutation = useMutation({
    // Each tool's state reaches the cards as soon as it lands, so the user
    // sees Trivy ready while the database still downloads.
    mutationFn: async ({ version, force }: { version?: string; force: boolean }) => {
      if (tools.missing.includes("trivy")) {
        queryClient.setQueryData(["tools"], await updateTrivy(force, version))
      }
      return updateTrivyDB()
    },
    onSuccess: (state) => queryClient.setQueryData(["tools"], state),
  })

  const saveKeyMutation = useMutation({
    mutationFn: (signatureKey: string) => updateSettings({ ...settingsQuery.data!, signatureKey }),
    onSuccess: () => {
      setKeyValue("")
      void queryClient.invalidateQueries({ queryKey: ["tools"] })
    },
  })

  const missingTrivy = tools.missing.includes("trivy")
  const missingDb = tools.missing.includes("trivy-db")
  const missingKey = tools.missing.includes("signature-key")
  const needsInstall = missingTrivy || missingDb

  const installError = installMutation.error instanceof ProblemError ? installMutation.error : null
  // A 409 from the install means the latest Trivy release is younger than the minimum release age.
  const latestTooRecent = installError?.status === 409
  const recommended = missingTrivy ? tools.trivyRecommended : undefined
  const install = (version?: string, force = false) => installMutation.mutate({ version, force })
  const installAnyway = (
    <Button variant="outline" size="sm" disabled={installMutation.isPending} onClick={() => install(undefined, true)}>
      Install Trivy {tools.trivyLatest} anyway
    </Button>
  )
  const saveKeyError = saveKeyMutation.error instanceof ProblemError ? saveKeyMutation.error : null

  return (
    <div className="animate-enter mx-auto flex w-full max-w-240 flex-1 flex-col gap-6 px-5 py-8">
      <div>
        <p className="text-xs font-semibold tracking-wide text-muted uppercase">First run</p>
        <h1 className="mt-1 text-2xl font-bold tracking-tight text-ink">Prepare sealift</h1>
        <p className="mt-1.5 max-w-[62ch] text-muted">
          sealift scans with Trivy and signs each archive with the key your Nexus import checks. Nothing downloads
          until you press Install.
        </p>
      </div>

      <div className="grid gap-3">
        <ToolRow
          icon={<ShieldCheck className="size-5" />}
          title={`Trivy ${tools.trivyActive || recommended || tools.trivyLatest}`.trim()}
          description="Vulnerability scanner, from github.com/aquasecurity/trivy, checked against its sha256."
          size={tools.latestSizeBytes > 0 && !recommended ? formatBytes(tools.latestSizeBytes) : undefined}
          ready={!missingTrivy}
          busy={installMutation.isPending && missingTrivy}
        />
        <ToolRow
          icon={<Database className="size-5" />}
          title="Vulnerability database"
          description={
            missingDb
              ? "Updated every six hours upstream. sealift refreshes it before each analysis."
              : `Downloaded ${formatDbDate(tools.trivyDbDate)}. sealift refreshes it before each analysis.`
          }
          size="about 120 MB"
          ready={!missingDb}
          busy={installMutation.isPending && !missingTrivy && missingDb}
        />
        <Card className="grid grid-cols-[40px_1fr_auto] items-center gap-3.5 p-4">
          <span
            className={
              "grid size-10 flex-none place-items-center rounded-[10px] border border-line " +
              (missingKey ? "bg-card text-muted" : "border-transparent bg-accent/15 text-accent")
            }
          >
            <KeyRound className="size-5" />
          </span>
          <div>
            <h3 className="text-sm font-semibold text-ink">Signature key</h3>
            <p className="text-sm text-muted">
              The value your Nexus import project expects in{" "}
              <code className="font-mono text-xs">signature.key</code>. Ask its owner if you do not have it.
            </p>
            {missingKey ? (
              <form
                className="mt-2.5 flex flex-wrap gap-2"
                onSubmit={(event) => {
                  event.preventDefault()
                  if (settingsQuery.data && keyValue.trim() && !saveKeyMutation.isPending) {
                    saveKeyMutation.mutate(keyValue.trim())
                  }
                }}
              >
                <input
                  type="password"
                  value={keyValue}
                  onChange={(event) => setKeyValue(event.target.value)}
                  placeholder="Paste the key"
                  autoComplete="off"
                  aria-label="Signature key"
                  className="h-9 min-w-55 flex-1 rounded-md border border-line bg-background px-3 text-sm outline-none focus:border-accent"
                />
                <Button type="submit" size="sm" disabled={!settingsQuery.data || !keyValue.trim() || saveKeyMutation.isPending}>
                  Save key
                </Button>
              </form>
            ) : null}
          </div>
          <span className={"inline-flex items-center gap-1.5 text-sm font-medium " + (missingKey ? "text-muted" : "text-severity-resolved-fg")}>
            {missingKey ? (
              "Required to export"
            ) : (
              <>
                <Check className="size-3.5" strokeWidth={3} /> Saved
              </>
            )}
          </span>
        </Card>
      </div>

      {saveKeyError ? <ProblemNotice status={saveKeyError.status} problem={saveKeyError.problem} /> : null}

      {needsInstall ? (
        <div className="flex flex-col items-start gap-3">
          <Button size="lg" disabled={installMutation.isPending} onClick={() => install(recommended)}>
            {installMutation.isPending
              ? "Installing…"
              : recommended
                ? `Install Trivy ${recommended} and its database`
                : tools.latestSizeBytes > 0
                  ? `Install Trivy (${formatBytes(tools.latestSizeBytes)}) and its database (about 120 MB, 1.4 GB once unpacked)`
                  : "Install Trivy and its database (about 120 MB, 1.4 GB once unpacked)"}
          </Button>
          {recommended ? (
            <div className="flex flex-col items-start gap-2 text-sm text-muted">
              <p>
                Trivy {tools.trivyLatest} came out {formatGoDuration(tools.trivyLatestAge)} ago. sealift waits before installing a new release, so a
                bad or compromised publish has time to surface, and proposes {recommended}, the newest release past that wait.
              </p>
              {installAnyway}
            </div>
          ) : null}
          {installError ? (
            <ProblemNotice status={installError.status} problem={installError.problem}>
              <div className="mt-2 flex flex-wrap gap-2">
                {latestTooRecent ? installAnyway : null}
                <Button variant="outline" size="sm" onClick={() => install(recommended)}>
                  Retry
                </Button>
              </div>
            </ProblemNotice>
          ) : null}
        </div>
      ) : missingKey ? (
        <p className="text-sm text-muted">Save the signature key to continue.</p>
      ) : (
        <Button size="lg" className="self-start" onClick={onContinue}>
          Continue
        </Button>
      )}
    </div>
  )
}

interface ToolRowProps {
  icon: ReactNode
  title: string
  description: string
  /** Download size shown while the tool is missing; omitted when unknown. */
  size?: string
  ready: boolean
  busy: boolean
}

function ToolRow({ icon, title, description, size, ready, busy }: ToolRowProps) {
  return (
    <Card data-tool className="grid grid-cols-[40px_1fr_auto] items-center gap-3.5 p-4">
      <span
        className={
          "grid size-10 flex-none place-items-center rounded-[10px] border border-line " +
          (ready ? "border-transparent bg-accent/15 text-accent" : "bg-card text-muted")
        }
      >
        {icon}
      </span>
      <div>
        <h3 className="text-sm font-semibold text-ink">{title}</h3>
        <p className="text-sm text-muted">{description}</p>
        {busy ? (
          <div className="mt-2.5 h-1.5 overflow-hidden rounded-full bg-line" aria-hidden="true">
            <div className="animate-indeterminate h-full w-1/3 rounded-full bg-accent" />
          </div>
        ) : null}
      </div>
      <span className={"inline-flex items-center gap-1.5 text-sm font-medium whitespace-nowrap " + (ready ? "text-severity-resolved-fg" : busy ? "text-ink" : "text-muted")}>
        {ready ? (
          <>
            <Check className="size-3.5" strokeWidth={3} /> Ready
          </>
        ) : busy ? (
          <>
            <LoaderCircle className="size-3.5 animate-spin" /> Downloading…
          </>
        ) : size ? (
          `Not installed · ${size}`
        ) : (
          "Not installed"
        )}
      </span>
    </Card>
  )
}
