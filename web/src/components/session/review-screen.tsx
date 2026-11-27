import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { ArrowRight, ArrowUpRight, ChevronDown, Info, LoaderCircle, Lock, Minus, Pause } from "lucide-react"
import { useEffect, useId, useState, type ReactNode } from "react"

import { ProblemError } from "@/api/client"
import { getProjectManifest, queueExport, type Analysis, type DependencyResult, type Project } from "@/api/projects"
import { ProblemNotice } from "@/components/problem-notice"
import { AnalysisWarnings } from "@/components/session/analysis-warnings"
import { ReadySummary } from "@/components/session/ready-summary"
import { ReasonsBlock } from "@/components/session/reasons-block"
import { DecidePanel, JumpPanel, SeverityCounts, VersionChange, releaseAge } from "@/components/session/review-panels"
import { StepBar, type StepId } from "@/components/step-bar"
import { Button } from "@/components/ui/button"
import { Term } from "@/components/ui/term"
import { useReasons, useSelection } from "@/hooks/use-selection"
import { exportSelection } from "@/lib/exportSelection"
import { parseManifestPreview } from "@/lib/manifestPreview"
import { reasonKey, reasonProblem, reasonsToSend, requiredReasons } from "@/lib/requiredReasons"
import { afterVectorOf, cveFix, cvesOf, familyOf, groupDependencies, pickedOf, type ReviewGroupKey } from "@/lib/reviewGroups"
import { sessionSteps } from "@/lib/sessionSteps"
import { cn } from "@/lib/utils"

interface ReviewScreenProps {
  project: Project
  analysis: Analysis
  onNavigateStep: (step: StepId) => void
}

const plural = (n: number, one: string, many: string) => `${n.toLocaleString("en-US")} ${n === 1 ? one : many}`
const total = (vector: number[]) => vector.reduce((sum, n) => sum + n, 0)
const minus = (a: number[], b: number[]) => a.map((n, i) => Math.max(0, n - (b[i] ?? 0)))

function andList(items: string[]): string {
  return items.length < 2 ? items.join("") : `${items.slice(0, -1).join(", ")} and ${items[items.length - 1]}`
}

type Opened = { kind: "decide" | "jump"; name: string }

export function ReviewScreen({ project, analysis, onNavigateStep }: ReviewScreenProps) {
  const queryClient = useQueryClient()
  const selection = useSelection(analysis.id)
  const reasons = useReasons(analysis.id)
  const [open, setOpen] = useState<Set<ReviewGroupKey>>(new Set())
  const [opened, setOpened] = useState<Opened | null>(null)
  const [focusAfter, setFocusAfter] = useState<string | null>(null)
  const causeId = useId()

  const result = analysis.result
  const dependencies = result?.dependencies ?? []
  const families = result?.families ?? []

  // Decide names a dev dependency, which only the stored package.json says.
  const manifestQuery = useQuery({
    queryKey: ["project", project.id, "manifest"],
    queryFn: () => getProjectManifest(project.id),
    enabled: opened?.kind === "decide",
    staleTime: Infinity,
  })

  // Seeded from the proposal, so a first Seal sends it untouched; re-runs when the analysis changes under
  // the same mounted screen.
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

  // A recorded jump moves its row into the reasons block: its new action takes the focus the old row held.
  useEffect(() => {
    if (focusAfter === null) return
    const timer = setTimeout(() => {
      document.querySelector<HTMLElement>(`[data-reason-action="${CSS.escape(focusAfter)}"]`)?.focus()
      setFocusAfter(null)
    }, 0)
    return () => clearTimeout(timer)
  }, [focusAfter])

  const toExport = exportSelection(dependencies, selection.selection)
  const needed = result ? requiredReasons(result, toExport) : []
  const waiting = needed.filter((n) => {
    const text = reasons.reasons[reasonKey(n)] ?? ""
    return text.trim() === "" || reasonProblem(text) !== undefined
  })

  const sealMutation = useMutation({
    mutationFn: () =>
      queueExport(project.id, analysis.id, {
        selection: toExport,
        includeProject: false,
        reasons: reasonsToSend(needed, reasons.reasons),
      }),
    onSuccess: (created) => {
      queryClient.setQueryData(["project", project.id], (prev: Project | undefined) =>
        prev ? { ...prev, exports: [...(prev.exports ?? []), created] } : prev,
      )
      onNavigateStep("export")
    },
  })
  const sealError = sealMutation.error instanceof ProblemError ? sealMutation.error : null
  // internal/api answers a selection whose reasons fall short with this title and one problem per line of its detail.
  const refusal =
    sealError?.status === 400 && sealError.problem?.title === "invalid export reasons" ? (sealError.problem.detail ?? undefined) : undefined

  const steps = sessionSteps({ project, analysis, current: "review", onNavigate: onNavigateStep })

  if (!result) {
    return (
      <div className="animate-enter mx-auto flex w-full max-w-190 flex-1 flex-col px-5 py-9">
        <StepBar steps={steps} />
        <div className="flex flex-col items-start gap-3">
          <p className="text-muted">
            {analysis.state === "failed" || analysis.state === "cancelled" || analysis.state === "interrupted"
              ? "This analysis did not finish, so there is nothing to review."
              : "The analysis is still running. Its review opens here once it finishes."}
          </p>
          <Button onClick={() => onNavigateStep("analysis")}>Go to the analysis</Button>
        </div>
      </div>
    )
  }

  const picked = (dependency: DependencyResult) => pickedOf(dependency, selection.selection[dependency.name])
  const groups = groupDependencies(dependencies, selection.selection, families)
  const departs = dependencies.some((d) => picked(d) !== (d.best || d.current))
  // The combined check measured the proposal only; any other selection sums each package's own scan.
  const checkedTogether = !departs && result.after !== undefined
  const after = checkedTogether && result.after ? result.after : afterVectorOf(dependencies, picked)
  const ready = waiting.length === 0
  const changed = Object.keys(toExport).length

  const hasCveBand = needed.some((n) => n.kind === "cve-without-fix")
  const hasJumpBand = needed.some((n) => n.kind === "major-jump")
  // The severity's explanation goes to the first row on screen that shows severities, when neither Ready's head nor
  // a reason row shows them first.
  const severityRow = ready || hasCveBand
    ? undefined
    : (["updated", "kept", "unchanged"] as const)
        .filter((key) => open.has(key))
        .flatMap((key) => groups[key].map((d) => ({ key, d })))
        .find(({ key, d }) => total(rowVectors(key, d, picked(d)).flat()) > 0)

  // The server refuses an export that selects no version, so a recorded reason alone leaves nothing to seal.
  const title = ready ? (changed === 0 ? "Nothing to seal" : "Ready to seal") : waiting.length === 1 ? "One thing needs you" : `${plural(waiting.length, "thing", "things")} need you`
  const names = waiting.map((n) => n.label)
  const cause =
    names.length > 0
      ? `Opens once ${andList(names)} ${names.length === 1 ? "has" : "have"} a reason.`
      : changed === 0
        ? "Opens once a package changes version."
        : undefined

  function toggle(key: ReviewGroupKey) {
    setOpen((was) => {
      const next = new Set(was)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })
  }

  const openedDependency = opened ? dependencies.find((d) => d.name === opened.name) : undefined
  const membersOf = (dependency: DependencyResult) => {
    const family =
      familyOf(dependency, families) ??
      (dependency.family ? { name: dependency.family, members: dependencies.filter((d) => d.family === dependency.family).map((d) => d.name) } : undefined)
    return { family, members: family ? dependencies.filter((d) => family.members.includes(d.name)) : [dependency] }
  }
  const dev = (() => {
    if (!manifestQuery.data || !openedDependency) return false
    try {
      return parseManifestPreview(manifestQuery.data, project.name).dependencies.some((d) => d.name === openedDependency.name && d.kind === "dev")
    } catch {
      return false
    }
  })()

  return (
    <div className="animate-enter mx-auto flex w-full max-w-190 flex-1 flex-col px-5 py-9">
      <StepBar steps={steps} />

      <div className={ready ? "mb-1" : "mb-5"}>
        <h1 className="text-[28px] font-bold tracking-tight text-ink">{title}</h1>
        {ready ? null : (
          <p data-known-cves className="mt-1 flex flex-wrap items-center gap-x-1.5 text-[15px] text-muted">
            <span>Known CVEs</span>{" "}
            <span className="figure text-ink-2">{total(result.before).toLocaleString("en-US")}</span>
            <ArrowRight aria-hidden="true" className="size-3.5" />
            <span className="sr-only"> to </span>
            <span className="figure text-ink">{total(after).toLocaleString("en-US")}</span>
            {hasCveBand ? null : <Term id="cve" prefer="above" />}
          </p>
        )}
      </div>
      {ready ? <ReadySummary before={result.before} after={after} checkedTogether={checkedTogether} directDependencies={dependencies.length} /> : null}

      <AnalysisWarnings warnings={result.warnings} />

      <ReasonsBlock
        needed={needed}
        reasons={reasons.reasons}
        result={result}
        refusal={refusal}
        explainCves={!ready}
        onDecide={(name) => setOpened({ kind: "decide", name })}
        onJump={(name) => setOpened({ kind: "jump", name })}
      />

      {(["updated", "kept", "unchanged"] as const).some((key) => groups[key].length > 0) ? (
        <div className="overflow-hidden rounded-xl border border-rule bg-bg">
          {(["updated", "kept", "unchanged"] as const)
            .filter((key) => groups[key].length > 0)
            .map((key, index) => (
              <Group
                key={key}
                kind={key}
                first={index === 0}
                dependencies={groups[key]}
                picked={picked}
                open={open.has(key)}
                onToggle={() => toggle(key)}
                explainJump={key === "kept" && !hasJumpBand}
                severityAt={severityRow?.key === key ? severityRow.d.name : undefined}
                onJump={(name) => setOpened({ kind: "jump", name })}
              />
            ))}
        </div>
      ) : null}

      <div className="mt-7 flex flex-wrap items-center justify-end gap-x-4 gap-y-2">
        {cause ? (
          <p id={causeId} className="text-[13px] text-muted [overflow-wrap:anywhere]">
            {cause}
          </p>
        ) : null}
        <Button
          size="page"
          aria-disabled={cause || sealMutation.isPending ? true : undefined}
          aria-describedby={cause ? causeId : undefined}
          onClick={() => {
            if (!cause && !sealMutation.isPending) sealMutation.mutate()
          }}
        >
          {sealMutation.isPending ? <LoaderCircle aria-hidden="true" className="motion-safe:animate-spin" /> : <Lock aria-hidden="true" />}
          {sealMutation.isPending ? "Sealing" : "Seal"}
        </Button>
      </div>
      {sealError && refusal === undefined ? <ProblemNotice status={sealError.status} problem={sealError.problem} className="mt-3" /> : null}

      {opened?.kind === "decide" && openedDependency ? (
        <DecidePanel
          dependency={openedDependency}
          version={picked(openedDependency)}
          dev={dev}
          advisories={result.advisories}
          reason={reasons.reasons[`cve-without-fix:${openedDependency.name}`] ?? ""}
          onClose={() => setOpened(null)}
          onRecord={(choice) => {
            if (choice.carry) reasons.setReason(`cve-without-fix:${openedDependency.name}`, choice.reason)
            else selection.pick(openedDependency.name, openedDependency.current, openedDependency.current)
            setOpened(null)
          }}
        />
      ) : null}
      {opened?.kind === "jump" && openedDependency
        ? (() => {
            const { family, members } = membersOf(openedDependency)
            const label = openedDependency.family || openedDependency.name
            return (
              <JumpPanel
                dependency={openedDependency}
                family={family}
                members={members}
                reason={reasons.reasons[`major-jump:${label}`] ?? ""}
                onClose={() => setOpened(null)}
                onRecord={(choice) => {
                  for (const member of members) {
                    if (choice.jump) {
                      if (member.jump) selection.pick(member.name, member.jump, member.current)
                    } else {
                      const best = member.candidates.find((c) => c.version === member.best)
                      selection.pick(member.name, best && !best.leavesLine ? best.version : member.current, member.current)
                    }
                  }
                  if (choice.jump) {
                    reasons.setReason(`major-jump:${label}`, choice.reason)
                    setFocusAfter(label)
                  }
                  setOpened(null)
                }}
              />
            )
          })()
        : null}
    </div>
  )
}

/** A row's counts: what the change fixes and what the held version keeps. */
function rowVectors(kind: ReviewGroupKey, dependency: DependencyResult, picked: string): [number[], number[]] {
  const held = picked === dependency.current ? dependency.vector : (dependency.candidates.find((c) => c.version === picked)?.vector ?? dependency.vector)
  return kind === "updated" ? [minus(dependency.vector, held), held] : [[0, 0, 0, 0, 0], held]
}

/** The versions that fix what a held version keeps, as its CVEs name them. */
function fixesOf(dependency: DependencyResult, picked: string): string[] {
  return [
    ...new Set(
      cvesOf(dependency, picked).flatMap((cve) => {
        const fix = cveFix(cve)
        return fix.kind === "fixed-in" ? [fix.versions] : []
      }),
    ),
  ]
}

const GROUPS: Record<Exclude<ReviewGroupKey, "reasons">, { icon: typeof Minus; words: string }> = {
  updated: { icon: ArrowUpRight, words: "updated" },
  kept: { icon: Pause, words: "kept on their major" },
  unchanged: { icon: Minus, words: "unchanged" },
}

interface GroupProps {
  kind: Exclude<ReviewGroupKey, "reasons">
  first: boolean
  dependencies: DependencyResult[]
  picked: (dependency: DependencyResult) => string
  open: boolean
  onToggle: () => void
  explainJump: boolean
  /** The dependency whose row explains severities, when this group holds the first one. */
  severityAt?: string
  onJump: (name: string) => void
}

function Group({ kind, first, dependencies, picked, open, onToggle, explainJump, severityAt, onJump }: GroupProps) {
  const look = GROUPS[kind]
  const Icon = look.icon
  const vectors = dependencies.map((d) => rowVectors(kind, d, picked(d)))
  const fixed = total(vectors.flatMap(([f]) => f))
  const left = total(vectors.flatMap(([, l]) => l))
  const summary =
    kind === "updated" ? { n: fixed, words: fixed === 1 ? "known CVE fixed" : "known CVEs fixed" } : kind === "kept" && left > 0 ? { n: left, words: left === 1 ? "known CVE left" : "known CVEs left" } : undefined
  const th = "py-2 pr-3 text-left text-xs font-semibold text-muted"

  return (
    <div data-group={kind} className={cn(!first && "border-t border-rule")}>
      <div className="flex items-center pr-2">
        <button
          type="button"
          aria-expanded={open}
          onClick={onToggle}
          className="flex min-h-14 min-w-0 flex-1 flex-wrap items-center gap-x-3 gap-y-0.5 px-4 py-2 text-left transition-colors duration-150 [@media(hover:hover)_and_(pointer:fine)]:hover:bg-hover"
        >
          <Icon aria-hidden="true" className="size-4 flex-none text-ink-2" />
          <span className="text-[15px] text-ink-2">
            <span className="figure text-ink">{plural(dependencies.length, "package", "packages")}</span> {look.words}
          </span>
          {summary ? (
            <span className="ml-auto text-[13px] text-muted">
              <span className="figure text-ink">{summary.n.toLocaleString("en-US")}</span> {summary.words}
            </span>
          ) : <span className="ml-auto" />}
          <ChevronDown aria-hidden="true" className={cn("size-4 flex-none text-muted transition-transform duration-200 ease-out motion-reduce:transition-none", !open && "-rotate-90")} />
        </button>
        {explainJump ? <Term id="major-jump" /> : null}
      </div>
      {open ? (
        <div className="animate-fade overflow-x-auto px-4 pb-3">
          <table className="w-full min-w-[34rem] text-[13px]">
            <thead>
              <tr className="border-b border-rule">
                <th scope="col" className={th}>Package</th>
                <th scope="col" className={th}>{kind === "kept" ? "Kept to next major" : "Version"}</th>
                <th scope="col" className={th}>{kind === "updated" ? "Known CVEs fixed" : "Known CVEs"}</th>
                {kind === "updated" ? <th scope="col" className={th}>Left</th> : null}
                {kind === "updated" ? <th scope="col" className={th}>Release age</th> : null}
                {kind === "kept" ? <th scope="col" className={cn(th, "pr-0")}><span className="sr-only">Jump</span></th> : null}
              </tr>
            </thead>
            <tbody>
              {dependencies.map((dependency, index) => {
                const version = picked(dependency)
                const [fixedVector, leftVector] = vectors[index]
                const candidate = dependency.candidates.find((c) => c.version === version)
                const notes = (candidate?.signals ?? []).filter((s) => s.name === "publisher-changed")
                const fixes = fixesOf(dependency, version)
                const explain = severityAt === dependency.name ? <Term id="severity" /> : null
                return (
                  <tr key={dependency.name} className="border-b border-rule last:border-b-0">
                    <td className="py-2 pr-3 align-top">
                      <span className="font-medium text-ink [overflow-wrap:anywhere]">{dependency.name}</span>
                      {notes.map((signal) => (
                        <span key={signal.name} className="mt-0.5 flex items-start gap-1 text-xs text-muted">
                          <Info aria-hidden="true" className="mt-0.5 size-3 flex-none" />
                          <span className="[overflow-wrap:anywhere]">{signal.evidence}</span>
                        </span>
                      ))}
                    </td>
                    <td className="py-2 pr-3 align-top">
                      {kind === "unchanged" ? (
                        <span className="font-mono text-[12.5px] text-ink-2 [font-variant-ligatures:none] [overflow-wrap:anywhere]">{dependency.current}</span>
                      ) : (
                        <VersionChange before={dependency.current} after={kind === "kept" ? (dependency.jump ?? version) : version} />
                      )}
                    </td>
                    <td className="py-2 pr-3 align-top">
                      <span className="inline-flex flex-wrap items-center gap-x-1">
                        <SeverityCounts vector={kind === "updated" ? fixedVector : leftVector} />
                        {kind !== "updated" || total(fixedVector) > 0 ? explain : null}
                      </span>
                      {kind !== "updated" && fixes.length > 0 ? <FixedIn fixes={fixes} /> : null}
                    </td>
                    {kind === "updated" ? (
                      <td className="py-2 pr-3 align-top">
                        <span className="inline-flex flex-wrap items-center gap-x-1">
                          <SeverityCounts vector={leftVector} />
                          {total(fixedVector) > 0 ? null : explain}
                        </span>
                        {fixes.length > 0 ? <FixedIn fixes={fixes} /> : null}
                      </td>
                    ) : null}
                    {kind === "updated" ? <td className="py-2 pr-3 align-top whitespace-nowrap text-ink-2">{releaseAge(candidate?.published) ?? "no date"}</td> : null}
                    {kind === "kept" ? (
                      <td className="py-1 text-right align-top">
                        <Button type="button" variant="outline" size="sm" aria-label={`Jump ${dependency.name}`} onClick={() => onJump(dependency.name)}>
                          <ArrowUpRight aria-hidden="true" />
                          Jump
                        </Button>
                      </td>
                    ) : null}
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      ) : null}
    </div>
  )
}

function FixedIn({ fixes }: { fixes: string[] }): ReactNode {
  return (
    <span className="mt-0.5 block text-xs text-muted [overflow-wrap:anywhere]">
      fixed in <span className="font-mono text-ink-2 [font-variant-ligatures:none]">{fixes.join(", ")}</span>
    </span>
  )
}
