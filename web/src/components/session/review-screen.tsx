import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Link, useNavigate } from "@tanstack/react-router"
import { ChevronRight, CircleAlert, Info } from "lucide-react"
import { useEffect, useState } from "react"

import { ProblemError } from "@/api/client"
import { queueExport, type Analysis, type Candidate, type DependencyResult, type Project } from "@/api/projects"
import { getSettings } from "@/api/settings"
import { ProblemNotice } from "@/components/problem-notice"
import { SeverityCounts } from "@/components/severity-counts"
import { StepBar, type StepId } from "@/components/step-bar"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card } from "@/components/ui/card"
import { useSelection } from "@/hooks/use-selection"
import {
  afterVectorOf,
  groupDependencies,
  jumpKind,
  reasonFor,
  type ReviewGroupKey,
} from "@/lib/reviewGroups"
import { sessionSteps } from "@/lib/sessionSteps"
import { cn, humanizeSignal, releasedAgo } from "@/lib/utils"

interface ReviewScreenProps {
  project: Project
  analysis: Analysis
  onNavigateStep: (step: StepId) => void
}

const GROUP_COPY: Record<ReviewGroupKey, { title: string; why: string }> = {
  decide: { title: "To decide", why: "Breaking change possible, or a signal worth a second look" },
  proposed: { title: "Proposed", why: "Safe jumps that fix CVEs" },
  nothing: { title: "Nothing to do", why: "No CVEs, or no newer version helps" },
}

const SEVERITY_DOT: Record<string, string> = {
  critical: "bg-severity-critical",
  high: "bg-severity-high",
  medium: "bg-severity-medium",
  low: "bg-severity-low",
  unknown: "bg-severity-unknown",
}

export function ReviewScreen({ project, analysis, onNavigateStep }: ReviewScreenProps) {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const settingsQuery = useQuery({ queryKey: ["settings"], queryFn: getSettings })
  const selection = useSelection(analysis.id)
  const [open, setOpen] = useState<Set<string>>(new Set())
  const [nothingOpen, setNothingOpen] = useState(false)

  const result = analysis.result
  const dependencies = result?.dependencies ?? []

  // Seeded from sealift's own best pick, so the initial export matches the
  // proposal without the user touching anything; re-runs if the analysis
  // (and so its dependency list) changes under the same mounted screen.
  useEffect(() => {
    const defaults: Record<string, string[]> = {}
    for (const dependency of dependencies) {
      if (dependency.best) {
        defaults[dependency.name] = [dependency.best]
      }
    }
    selection.seedDefaults(defaults)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [analysis.id, dependencies])

  function pickedVersionOf(dependency: DependencyResult): string {
    return selection.selected(dependency.name, dependency.current)
  }

  const changedDependencies = dependencies.filter((d) => pickedVersionOf(d) !== d.current)

  const confirmMutation = useMutation({
    mutationFn: () =>
      queueExport(project.id, analysis.id, {
        selection: Object.fromEntries(changedDependencies.map((d) => [d.name, [pickedVersionOf(d)]])),
        includeProject: false,
      }),
    onSuccess: (created) => {
      queryClient.setQueryData(["project", project.id], (prev: Project | undefined) =>
        prev ? { ...prev, exports: [...(prev.exports ?? []), created] } : prev,
      )
      void navigate({ to: "/sessions/$sessionId/export", params: { sessionId: project.id } })
    },
  })
  const confirmError = confirmMutation.error instanceof ProblemError ? confirmMutation.error : null
  const missingSignatureKey =
    confirmError?.status === 400 && !confirmError.problem?.errors?.length && confirmError.problem?.detail?.includes("signatureKey")

  const steps = sessionSteps({ project, current: "review", onNavigate: onNavigateStep })

  if (!result) {
    return (
      <div className="animate-enter mx-auto flex w-full max-w-240 flex-1 flex-col px-5 py-8">
        <StepBar steps={steps} />
        <p className="p-8 text-muted">No finished analysis to review yet.</p>
      </div>
    )
  }

  const groups = groupDependencies(dependencies)
  const before = dependencies.reduce<number[]>(
    (total, d) => total.map((count, i) => count + (d.vector[i] ?? 0)),
    [0, 0, 0, 0, 0],
  )
  const after = afterVectorOf(dependencies, pickedVersionOf)
  const beforeTotal = before.reduce((a, b) => a + b, 0)
  const afterTotal = after.reduce((a, b) => a + b, 0)
  const fixedCritical = before[0] - after[0]

  function toggleOpen(name: string) {
    setOpen((prev) => {
      const next = new Set(prev)
      if (next.has(name)) {
        next.delete(name)
      } else {
        next.add(name)
      }
      return next
    })
  }

  return (
    <div className="animate-enter mx-auto flex w-full max-w-240 flex-1 flex-col px-5 py-8 pb-28">
      <StepBar steps={steps} />

      <div className="mb-6">
        <h1 className="text-2xl font-bold tracking-tight text-ink">Review the proposal</h1>
        <p className="mt-1.5 max-w-[62ch] text-muted">
          sealift picked a version for each dependency. Check the ones marked to decide, open any row to choose
          another version, then confirm.
        </p>
      </div>

      <Card>
        <div className="grid grid-cols-1 items-center gap-4 p-5 sm:grid-cols-[1fr_auto_1fr]">
          <div>
            <p className="mb-1.5 text-xs text-muted">Today · {beforeTotal} CVEs</p>
            <SeverityCounts vector={before} />
          </div>
          <span className="hidden text-muted sm:inline" aria-hidden>
            →
          </span>
          <div>
            <p className="mb-1.5 text-xs text-muted">With this selection · {afterTotal} CVEs</p>
            <SeverityCounts vector={after} />
          </div>
        </div>
        <div className="border-t border-line px-5 py-3.5 text-sm text-muted">
          <span className="font-semibold text-ink">
            {beforeTotal - afterTotal} CVE{beforeTotal - afterTotal === 1 ? "" : "s"} fixed
          </span>
          {fixedCritical > 0 ? `, including ${fixedCritical} critical` : ""}, by changing {changedDependencies.length}{" "}
          of {dependencies.length} dependencies.
        </div>
      </Card>

      <p className="mt-4 max-w-[70ch] text-sm text-muted">
        sealift proposes the oldest version that fixes the most CVEs: a release with no known CVE may simply be too
        new to have any, and older ones have had more eyes on them.
        {settingsQuery.data ? ` Releases younger than ${settingsQuery.data.minReleaseAgeDays} days are held back.` : ""}
      </p>

      {(["decide", "proposed", "nothing"] as const).map((key) => {
        const list = groups[key]
        if (list.length === 0) {
          return null
        }
        const copy = GROUP_COPY[key]
        if (key === "nothing") {
          return (
            <section key={key} className="mt-7">
              <div className="mb-2.5 flex items-baseline gap-2.5">
                <h2 className="text-lg font-semibold text-ink">{copy.title}</h2>
                <span className="text-sm text-muted">{list.length}</span>
              </div>
              <button
                type="button"
                className="text-sm font-medium text-accent"
                aria-expanded={nothingOpen}
                onClick={() => setNothingOpen((v) => !v)}
              >
                {nothingOpen ? "Hide" : "Show"} {list.length} dependencies
              </button>
              {nothingOpen ? (
                <Card className="mt-2.5">
                  {list.map((dependency, index) => (
                    <div key={dependency.name} className={cn("px-4.5 py-3.5 text-sm", index > 0 && "border-t border-line")}>
                      <span className="font-mono font-semibold text-ink">{dependency.name}</span>
                      <span className="ml-2 text-muted">{dependency.current}</span>
                      <p className="mt-1 text-xs text-muted">
                        {dependency.candidates.length} newer version{dependency.candidates.length === 1 ? "" : "s"} exist;
                        none changes the CVE picture.
                      </p>
                    </div>
                  ))}
                </Card>
              ) : null}
            </section>
          )
        }
        return (
          <section key={key} className="mt-7">
            <div className="mb-2.5 flex items-baseline gap-2.5">
              <h2 className="text-lg font-semibold text-ink">{copy.title}</h2>
              <span className="text-sm text-muted">{list.length}</span>
              <span className="ml-auto text-sm text-muted">{copy.why}</span>
            </div>
            <Card>
              {list.map((dependency, index) => (
                <DependencyRow
                  key={dependency.name}
                  dependency={dependency}
                  isFirst={index === 0}
                  isOpen={open.has(dependency.name)}
                  onToggle={() => toggleOpen(dependency.name)}
                  picked={pickedVersionOf(dependency)}
                  onPick={(version) => selection.pick(dependency.name, version, dependency.current)}
                />
              ))}
            </Card>
          </section>
        )
      })}

      <div className="fixed inset-x-0 bottom-0 z-10 border-t border-line bg-background/95 backdrop-blur">
        <div className="mx-auto flex w-full max-w-240 flex-wrap items-center justify-between gap-4 px-5 py-3.5">
          <span className="text-sm">
            <span className="font-semibold text-ink">
              {changedDependencies.length} change{changedDependencies.length === 1 ? "" : "s"}
            </span>
            <span className="text-muted"> · {afterTotal} CVEs left</span>
          </span>
          <div className="flex flex-col items-end gap-2">
            <Button
              size="lg"
              disabled={changedDependencies.length === 0 || confirmMutation.isPending}
              onClick={() => confirmMutation.mutate()}
            >
              {confirmMutation.isPending ? "Building…" : "Confirm and build the archive"}
            </Button>
          </div>
        </div>
        {confirmError ? (
          <div className="mx-auto w-full max-w-240 px-5 pb-3.5">
            <ProblemNotice status={confirmError.status} problem={confirmError.problem}>
              {missingSignatureKey ? (
                <Link to="/settings" className="mt-2 inline-block text-accent underline">
                  Go to Settings
                </Link>
              ) : null}
            </ProblemNotice>
          </div>
        ) : null}
      </div>
    </div>
  )
}

interface DependencyRowProps {
  dependency: DependencyResult
  isFirst: boolean
  isOpen: boolean
  onToggle: () => void
  picked: string
  onPick: (version: string) => void
}

function DependencyRow({ dependency, isFirst, isOpen, onToggle, picked, onPick }: DependencyRowProps) {
  const kept = picked === dependency.current
  const kind = kept ? null : jumpKind(dependency.current, picked)
  const defaultCandidates = dependency.candidates.filter((c) => c.key || c.version === dependency.best)
  const extraCandidates = dependency.candidates.filter((c) => !defaultCandidates.includes(c))
  const [showAll, setShowAll] = useState(false)
  const shownCandidates = showAll ? dependency.candidates : defaultCandidates
  const cveTotal = dependency.vector.reduce((a, b) => a + b, 0)
  const extraCves = cveTotal - dependency.cves.length

  return (
    <div className={cn(isFirst ? "" : "border-t border-line")}>
      <button
        type="button"
        className="grid w-full grid-cols-[minmax(0,1.2fr)_minmax(0,1.4fr)_auto] items-center gap-3.5 px-4.5 py-3.5 text-left hover:bg-card"
        aria-expanded={isOpen}
        onClick={onToggle}
      >
        <span>
          <span className="font-mono text-sm font-semibold text-ink">{dependency.name}</span>
          <p className="mt-0.5 text-xs text-muted">{reasonFor(dependency, picked)}</p>
        </span>
        <span className="flex flex-wrap items-center gap-2 font-mono text-sm">
          <span className="text-muted">{dependency.current}</span>
          <span className="text-muted" aria-hidden>
            →
          </span>
          <span className={kept ? "font-semibold text-muted" : "font-semibold text-accent"}>{picked}</span>
          {kind && kind !== "minor-or-patch" ? (
            <Badge className="border-severity-high/35 bg-transparent text-severity-high">
              {kind === "major" ? "Major" : "0.x, may break"}
            </Badge>
          ) : null}
        </span>
        <ChevronRight className={cn("size-4.5 text-muted transition-transform", isOpen && "rotate-90")} />
      </button>

      {isOpen ? (
        <div className="animate-enter px-4.5 pb-4.5">
          <p className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted">
            Current {dependency.current} · {cveTotal} CVE{cveTotal === 1 ? "" : "s"}
          </p>
          <div className="mb-3 flex flex-wrap gap-1.5">
            {dependency.cves.map((cve) => (
              <span key={cve.id} className="inline-flex items-center gap-1.5 rounded-md border border-line px-2 py-0.5 font-mono text-xs">
                <span className={cn("size-1.5 rounded-full", SEVERITY_DOT[cve.severity.toLowerCase()] ?? "bg-severity-unknown")} />
                {cve.id}
              </span>
            ))}
            {extraCves > 0 ? <span className="rounded-md border border-line px-2 py-0.5 font-mono text-xs text-muted">+{extraCves} more</span> : null}
          </div>

          <div className="grid gap-1.5">
            {shownCandidates.map((candidate) => (
              <CandidateRow
                key={candidate.version}
                dependency={dependency}
                candidate={candidate}
                selected={picked === candidate.version}
                onPick={() => onPick(candidate.version)}
              />
            ))}
            <button
              type="button"
              className={cn(
                "grid grid-cols-[22px_minmax(0,1fr)_auto] items-start gap-3 rounded-lg border p-3 text-left",
                kept ? "border-accent shadow-[0_0_0_3px_var(--color-accent)]/15" : "border-line hover:border-accent/50",
              )}
              onClick={() => onPick(dependency.current)}
            >
              <Radio selected={kept} />
              <span>
                <span className="font-mono text-sm font-semibold text-ink">{dependency.current}</span>{" "}
                <span className="text-sm text-muted">Keep the current version</span>
              </span>
              <SeverityCounts vector={dependency.vector} />
            </button>
          </div>

          {extraCandidates.length > 0 ? (
            <button type="button" className="mt-2 py-1.5 text-sm font-medium text-accent" onClick={() => setShowAll((v) => !v)}>
              {showAll ? "Show fewer versions" : `Show all ${dependency.candidates.length} newer versions`}
            </button>
          ) : null}
        </div>
      ) : null}
    </div>
  )
}

interface CandidateRowProps {
  dependency: DependencyResult
  candidate: Candidate
  selected: boolean
  onPick: () => void
}

function CandidateRow({ dependency, candidate, selected, onPick }: CandidateRowProps) {
  const blocking = candidate.signals.filter((s) => s.blocking)
  const notable = candidate.signals.filter((s) => !s.blocking)
  const blocked = blocking.length > 0
  const isBest = candidate.version === dependency.best

  return (
    <button
      type="button"
      disabled={blocked}
      aria-disabled={blocked}
      className={cn(
        "grid grid-cols-[22px_minmax(0,1fr)_auto] items-start gap-3 rounded-lg border p-3 text-left",
        blocked && "cursor-not-allowed opacity-70",
        selected && "border-accent shadow-[0_0_0_3px_var(--color-accent)]/15",
        !selected && !blocked && "border-line hover:border-accent/50",
        !selected && blocked && "border-line",
      )}
      onClick={onPick}
    >
      <Radio selected={selected} />
      <span>
        <span className="font-mono text-sm font-semibold text-ink">{candidate.version}</span>
        {isBest ? <span className="ml-1.5 text-xs text-muted">· proposed</span> : null}
        <p className="mt-0.5 text-xs text-muted">
          {candidate.published ? releasedAgo(candidate.published) : "publication date unknown"}
        </p>
        {blocking.map((signal) => (
          <p key={signal.name} className="mt-1 flex items-start gap-1.5 text-xs text-severity-critical-fg">
            <CircleAlert className="mt-0.5 size-3 flex-none" />
            <span>{signal.evidence}</span>
          </p>
        ))}
        {notable.map((signal) => (
          <p key={signal.name} className="mt-1 flex items-start gap-1.5 text-xs text-muted">
            <Info className="mt-0.5 size-3 flex-none" />
            <span>
              {signal.name === "publisher-changed" ? signal.evidence : `${humanizeSignal(signal.name)}: ${signal.evidence}`}
            </span>
          </p>
        ))}
      </span>
      <SeverityCounts vector={candidate.vector} />
    </button>
  )
}

function Radio({ selected }: { selected: boolean }) {
  return (
    <span className={cn("mt-0.5 grid size-4.5 place-items-center rounded-full border-1.5", selected ? "border-accent" : "border-line")}>
      {selected ? <span className="size-2 rounded-full bg-accent" /> : null}
    </span>
  )
}
