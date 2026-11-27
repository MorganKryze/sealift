import { useMutation, useQueryClient } from "@tanstack/react-query"
import { useNavigate } from "@tanstack/react-router"
import { ArrowRight, ArrowUpRight, ChevronDown, CircleAlert, CircleX, Cpu, FileText, FileUp, LoaderCircle, Lock, Minus, Package, PackageX, Plus, Shield } from "lucide-react"
import { useId, useState, type ReactNode } from "react"

import { ProblemError } from "@/api/client"
import { queueExport, type Analysis, type Project } from "@/api/projects"
import type { components } from "@/api/schema"
import { ProblemNotice } from "@/components/problem-notice"
import { PUBLISHES } from "@/components/session/analysis-screen"
import { AnalysisWarnings } from "@/components/session/analysis-warnings"
import { CveTable, ReasonBand, ReasonRow } from "@/components/session/reasons-block"
import { PinnedIn, PipDecidePanel, PipJumpPanel, SeverityCounts, SeverityMark, VersionChange, pipCve, severityOf } from "@/components/session/review-panels"
import { StepBar, type StepId } from "@/components/step-bar"
import { Button } from "@/components/ui/button"
import { Term } from "@/components/ui/term"
import { useReasons } from "@/hooks/use-selection"
import {
  pipCveTotals,
  pipGroups,
  pipNeededReasons,
  pipReasonsToSend,
  pipReasonWritten,
  pipVector,
  pipWaiting,
  wheelPlatform,
  withoutFix,
  type PipAnalysisResult,
  type PipGroupKey,
  type PipNeededReason,
  type PipPackage,
} from "@/lib/pipReview"
import { sessionSteps } from "@/lib/sessionSteps"
import { cn } from "@/lib/utils"

type PipTarget = components["schemas"]["PipTarget"]

const plural = (n: number, one: string, many: string) => `${n.toLocaleString("en-US")} ${n === 1 ? one : many}`
const total = (vector: number[]) => vector.reduce((sum, n) => sum + n, 0)
const andList = (items: string[]) => (items.length < 2 ? items.join("") : `${items.slice(0, -1).join(", ")} and ${items[items.length - 1]}`)
const mono = "font-mono text-[12.5px] [font-variant-ligatures:none] [overflow-wrap:anywhere]"
// A group lists this many rows before Show all.
const FIRST_ROWS = 12

/** The deployment's pip target in one line; on Check, its info button with the two commands that check it. */
export function PipTargetLine({ target, explain = false }: { target: PipTarget; explain?: boolean }) {
  return (
    <span>
      {explain ? "pip · " : null}Python <span className="figure text-ink-2">{target.python}</span> · {target.os} {target.cpu} · glibc{" "}
      <span className="figure text-ink-2">{target.glibc}</span>
      {explain ? (
        <>
          {" "}
          <Term id="target">
            <span className="mt-2 block font-medium text-ink">Check on one of them</span>
            <span className="mt-1 grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-1 font-mono text-xs [overflow-wrap:anywhere]">
              <span className="text-ink">python3 -VV</span>
              <span>{`Python ${target.python}`}</span>
              <span className="text-ink">ldd --version</span>
              <span>{`ldd (GNU libc) ${target.glibc}`}</span>
            </span>
          </Term>
        </>
      ) : null}
    </span>
  )
}

/** The Check step of a pip crossing read back: the files it was analysed from and its target. The server serves no file's content. */
export function PipCrossingCheck({ project, analysis, onNavigateStep }: { project: Project; analysis?: Analysis; onNavigateStep: (step: StepId) => void }) {
  const steps = sessionSteps({ project, analysis, current: "drop", onNavigate: onNavigateStep })
  const files = analysis?.pipResult?.files ?? []
  const target = analysis?.pipResult?.target ?? project.pipTarget
  return (
    <div className="animate-enter mx-auto flex w-full max-w-190 flex-1 flex-col px-5 py-9">
      <StepBar steps={steps} />
      <h1 className="text-[28px] font-bold tracking-tight text-ink [overflow-wrap:anywhere]">{`Update ${project.name}`}</h1>
      {target ? (
        <p className="mt-1 mb-5 text-muted">
          <PipTargetLine target={target} explain />
        </p>
      ) : null}
      {files.length > 0 ? (
        <div className="overflow-hidden rounded-xl border border-rule bg-bg">
          <p className="flex min-h-12 items-center gap-2.5 border-b border-rule px-4 py-2 text-[15px] text-ink-2">
            <FileText aria-hidden="true" className="size-4 flex-none text-ink-2" />
            <span className="figure text-ink">{plural(files.length, "requirements file", "requirements files")}</span>
          </p>
          <ul>
            {files.map((file) => (
              <li key={file} className={cn("border-b border-rule px-4 py-2.5 last:border-b-0 text-ink", mono)}>
                {file}
              </li>
            ))}
          </ul>
        </div>
      ) : (
        <p className="text-muted">This crossing lists its files once its analysis has read them.</p>
      )}
    </div>
  )
}

interface PipReviewScreenProps {
  project: Project
  analysis: Analysis
  onNavigateStep: (step: StepId) => void
}

type Opened = { kind: PipNeededReason["kind"]; name: string }

/**
 * The Review step of a pip crossing: what holds Seal first (a package with no wheel, then the reasons a
 * major jump, a CVE with no fix and a yanked release need), then the set against its previous crossing.
 * A reason is written in a panel, or the files are replaced by a new crossing of the project.
 */
export function PipReviewScreen({ project, analysis, onNavigateStep }: PipReviewScreenProps) {
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const reasons = useReasons(analysis.id)
  const [open, setOpen] = useState<Set<PipGroupKey>>(new Set())
  const [opened, setOpened] = useState<Opened | null>(null)
  const causeId = useId()
  const result = analysis.pipResult
  const needed = result ? pipNeededReasons(result) : []

  const sealMutation = useMutation({
    mutationFn: () => queueExport(project.id, analysis.id, { selection: {}, includeProject: false, reasons: pipReasonsToSend(needed, reasons.reasons) }),
    onSuccess: (created) => {
      queryClient.setQueryData(["project", project.id], (prev: Project | undefined) => (prev ? { ...prev, exports: [...(prev.exports ?? []), created] } : prev))
      onNavigateStep("export")
    },
  })
  const sealError = sealMutation.error instanceof ProblemError ? sealMutation.error : null
  const steps = sessionSteps({ project, analysis, current: "review", onNavigate: onNavigateStep })
  const replace = () => void navigate({ to: "/update", search: { from: project.id } })

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

  const waiting = pipWaiting(result, reasons.reasons)
  const groups = pipGroups(result)
  const totals = pipCveTotals(result)
  const things = waiting.noWheel.length + waiting.missing.length
  const title = things === 0 ? "Ready to seal" : things === 1 ? "One thing needs you" : `${plural(things, "thing", "things")} need you`
  const waitingNames = [...new Set(waiting.missing)]
  const cause =
    waiting.noWheel.length > 0
      ? `Opens once ${andList(waiting.noWheel)} ${waiting.noWheel.length === 1 ? "has" : "have"} a wheel for the target.`
      : waitingNames.length > 0
        ? `Opens once ${andList(waitingNames)} ${waitingNames.length === 1 ? "has" : "have"} a reason.`
        : undefined

  const byName = new Map(result.packages.map((pkg) => [pkg.name, pkg]))
  const order: PipGroupKey[] = result.previous ? ["changed", "added", "fix", "unchanged"] : ["fix", "packages"]
  const shown = order.filter((key) => groups[key].length > 0)
  const hasNoWheel = waiting.noWheel.length > 0
  const hasCveBand = needed.some((need) => need.kind === "cve-without-fix")
  // The severities are explained at the first row that shows them: the CVE band's, else the first open group's.
  const severityAt = hasCveBand
    ? undefined
    : shown
        .filter((key) => open.has(key))
        .flatMap((key) => groups[key].slice(0, FIRST_ROWS).map((pkg) => ({ key, pkg })))
        .find(({ key, pkg }) => total(rowVector(key, pkg)) > 0)
  const wheelAt = hasNoWheel ? undefined : shown.find((key) => open.has(key))

  function toggle(key: PipGroupKey) {
    setOpen((was) => {
      const next = new Set(was)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })
  }

  const openedPkg = opened ? byName.get(opened.name) : undefined
  const record = (kind: PipNeededReason["kind"], name: string) => (text: string) => {
    reasons.setReason(`${kind}:${name}`, text)
    setOpened(null)
  }

  return (
    <div className="animate-enter mx-auto flex w-full max-w-190 flex-1 flex-col px-5 py-9">
      <StepBar steps={steps} />

      <div className="mb-5">
        <h1 className="text-[28px] font-bold tracking-tight text-ink">{title}</h1>
        <p className="mt-1 flex flex-wrap items-center gap-x-1.5 text-[15px] text-muted">
          <span data-known-cves className="inline-flex flex-wrap items-center gap-x-1.5">
            <span>Known CVEs</span>
            <Term id="cve" prefer="above" />
            {totals.before ? (
              <>
                <span className="figure text-ink-2">{total(totals.before).toLocaleString("en-US")}</span>
                <ArrowRight aria-hidden="true" className="size-3.5" />
                <span className="sr-only"> to </span>
              </>
            ) : null}
            <span className="figure text-ink">{total(totals.after).toLocaleString("en-US")}</span>
          </span>
          <span aria-hidden="true">·</span>
          <Cpu aria-hidden="true" className="size-3.5" />
          <PipTargetLine target={result.target} />
        </p>
      </div>

      <AnalysisWarnings warnings={result.warnings} />

      {hasNoWheel ? <NoWheelBlock result={result} names={waiting.noWheel} onReplace={replace} /> : null}

      <PipReasons
        result={result}
        needed={needed}
        reasons={reasons.reasons}
        onOpen={(kind, name) => setOpened({ kind, name })}
      />

      {shown.length > 0 ? (
        <div className="overflow-hidden rounded-xl border border-rule bg-bg">
          {shown.map((key, index) => (
            <Group
              key={key}
              kind={key}
              first={index === 0}
              packages={groups[key]}
              open={open.has(key)}
              onToggle={() => toggle(key)}
              severityAt={severityAt?.key === key ? severityAt.pkg.name : undefined}
              explainWheel={wheelAt === key}
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
      {sealError ? <ProblemNotice status={sealError.status} problem={sealError.problem} className="mt-3" /> : null}

      {opened && openedPkg && opened.kind === "major-jump" ? (
        <PipJumpPanel
          pkg={openedPkg}
          reason={reasons.reasons[`major-jump:${openedPkg.name}`] ?? ""}
          onRecord={record("major-jump", openedPkg.name)}
          onReplace={replace}
          onClose={() => setOpened(null)}
        />
      ) : null}
      {opened && openedPkg && opened.kind !== "major-jump" ? (
        <PipDecidePanel
          pkg={openedPkg}
          kind={opened.kind}
          advisories={result.advisories}
          reason={reasons.reasons[`${opened.kind}:${openedPkg.name}`] ?? ""}
          onRecord={record(opened.kind, openedPkg.name)}
          onReplace={replace}
          onClose={() => setOpened(null)}
        />
      ) : null}
    </div>
  )
}

/** The red block of the packages the target cannot install, with Replace files in its band. */
function NoWheelBlock({ result, names, onReplace }: { result: PipAnalysisResult; names: string[]; onReplace: () => void }) {
  const heading = `${plural(names.length, "package", "packages")} with no wheel for the target`
  return (
    <section aria-label={heading} className="mb-3 overflow-hidden rounded-xl border border-bad-line bg-bg">
      <div className="flex min-h-12 flex-wrap items-center gap-x-2.5 gap-y-1 border-b border-bad-line/60 bg-bad-tint px-4 py-1.5">
        <CircleX aria-hidden="true" className="size-4 flex-none text-bad" />
        <p className="text-[13px] text-ink-2">
          <span className="figure text-bad">{plural(names.length, "package", "packages")}</span> with no wheel for the target
        </p>
        <Term id="wheel" />
        <Button type="button" variant="outline" className="ml-auto" onClick={onReplace}>
          <FileUp aria-hidden="true" />
          Replace files
        </Button>
      </div>
      <ul className="flex flex-col gap-1.5 p-1.5">
        {names.map((name) => {
          const pkg = result.packages.find((p) => p.name === name)
          const blocking = result.blocking.find((b) => b.name === name)
          const version = pkg?.version ?? blocking?.version ?? ""
          return (
            <li key={name} className="tinted-bad grid grid-cols-1 gap-x-3 gap-y-1 px-3 py-2.5 sm:grid-cols-[minmax(0,15rem)_minmax(0,1fr)]">
              <div className="min-w-0">
                <p className="flex flex-wrap items-baseline gap-x-1.5">
                  <span className="font-semibold text-ink [overflow-wrap:anywhere]">{name}</span>
                  <span className={cn(mono, "text-ink-2")}>{version}</span>
                </p>
                <PinnedIn pkg={{ pinnedAt: blocking?.pinnedAt ?? pkg?.pinnedAt, files: pkg?.files }} className="text-[12.5px] text-ink-2" />
              </div>
              <p className="min-w-0 text-[13px] text-ink sm:border-l sm:border-bad-line/60 sm:pl-3">{blocking ? (PUBLISHES[blocking.kind] ?? "Publishes no wheel for the target.") : "Publishes no wheel for the target."}</p>
            </li>
          )
        })}
      </ul>
    </section>
  )
}

interface PipReasonsProps {
  result: PipAnalysisResult
  needed: PipNeededReason[]
  reasons: Record<string, string>
  onOpen: (kind: PipNeededReason["kind"], name: string) => void
}

/** The three bands of reasons, as npm draws its two: major jumps, CVEs with no fix, yanked releases. */
function PipReasons({ result, needed, reasons, onOpen }: PipReasonsProps) {
  const id = useId()
  if (needed.length === 0) return null
  const byName = new Map(result.packages.map((pkg) => [pkg.name, pkg]))
  const rows = (kind: PipNeededReason["kind"]) => needed.filter((need) => need.kind === kind).flatMap((need) => (byName.has(need.name) ? [{ need, pkg: byName.get(need.name) as PipPackage }] : []))
  const jumps = rows("major-jump")
  const cves = rows("cve-without-fix")
  const yanked = rows("yanked")
  const carried = (list: { need: PipNeededReason }[]) => {
    const n = list.filter(({ need }) => pipReasonWritten(reasons[need.key])).length
    return n > 0 ? `, carried with ${plural(n, "reason", "reasons")}` : ""
  }
  const cveCount = new Set(cves.flatMap(({ pkg }) => pkg.cves.filter(withoutFix).map((cve) => cve.id))).size
  const firstSeverities = cves[0]?.need.key

  return (
    <section aria-label="Reasons" className="mb-3">
      <div className="overflow-hidden rounded-xl border border-rule bg-bg">
        {jumps.length > 0 ? (
          <div role="group" aria-labelledby={`${id}-jumps`}>
            <ReasonBand tone="info">
              <ArrowUpRight aria-hidden="true" className="size-4 flex-none text-info" />
              <p id={`${id}-jumps`} className="text-[13px] text-ink-2">
                <span className="figure text-ink">{plural(jumps.length, "major jump", "major jumps")}</span>
                {carried(jumps)}
              </p>
              <Term id="major-jump" />
            </ReasonBand>
            <ul className="flex flex-col gap-1.5 p-1.5">
              {jumps.map(({ need, pkg }) => (
                <ReasonRow key={need.key} text={reasons[need.key]} label={pkg.name} action="Jump" onAction={() => onOpen("major-jump", pkg.name)}>
                  <p data-reason-name className="font-semibold text-ink [overflow-wrap:anywhere]">
                    {pkg.name}
                  </p>
                  <VersionChange before={pkg.previous?.version ?? pkg.version} after={pkg.version} />
                </ReasonRow>
              ))}
            </ul>
          </div>
        ) : null}
        {cves.length > 0 ? (
          <div role="group" aria-labelledby={`${id}-cves`} className={cn(jumps.length > 0 && "border-t border-rule")}>
            <ReasonBand tone="warn">
              <CircleAlert aria-hidden="true" className="size-4 flex-none text-warn" />
              <p id={`${id}-cves`} className="text-[13px] text-ink-2">
                <span className="figure text-ink">{plural(cveCount, "known CVE", "known CVEs")}</span> with no fixed version
                {cves.length > 1 ? ` in ${plural(cves.length, "package", "packages")}` : ""}
                {carried(cves)}
              </p>
            </ReasonBand>
            <ul className="flex flex-col gap-1.5 p-1.5">
              {cves.map(({ need, pkg }) => {
                const kept = pkg.cves.filter(withoutFix).map(pipCve)
                const single = kept.length === 1 ? kept[0] : undefined
                return (
                  <ReasonRow
                    key={need.key}
                    text={reasons[need.key]}
                    label={pkg.name}
                    action="Decide"
                    onAction={() => onOpen("cve-without-fix", pkg.name)}
                    more={single ? undefined : { label: `${plural(kept.length, "CVE", "CVEs")} of ${pkg.name}`, content: <CveTable cves={kept} />, ruled: true }}
                  >
                    <PackageLine pkg={pkg} />
                    <div className="flex flex-wrap items-center gap-x-2">
                      {single ? (
                        <>
                          <span className="font-mono text-xs text-ink-2 [font-variant-ligatures:none] [overflow-wrap:anywhere]">{single.id}</span>
                          <SeverityMark severity={severityOf(single)} />
                        </>
                      ) : (
                        <SeverityCounts vector={pipVector(pkg.cves.filter(withoutFix))} />
                      )}
                      {need.key === firstSeverities ? <Term id="severity" /> : null}
                    </div>
                  </ReasonRow>
                )
              })}
            </ul>
          </div>
        ) : null}
        {yanked.length > 0 ? (
          <div role="group" aria-labelledby={`${id}-yanked`} className={cn((jumps.length > 0 || cves.length > 0) && "border-t border-rule")}>
            <ReasonBand tone="warn">
              <PackageX aria-hidden="true" className="size-4 flex-none text-warn" />
              <p id={`${id}-yanked`} className="text-[13px] text-ink-2">
                <span className="figure text-ink">{plural(yanked.length, "yanked release", "yanked releases")}</span>
                {carried(yanked)}
              </p>
              <Term id="yanked" />
            </ReasonBand>
            <ul className="flex flex-col gap-1.5 p-1.5">
              {yanked.map(({ need, pkg }) => (
                <ReasonRow key={need.key} text={reasons[need.key]} label={pkg.name} action="Decide" onAction={() => onOpen("yanked", pkg.name)}>
                  <PackageLine pkg={pkg} />
                  <PinnedIn pkg={pkg} className="text-[12.5px] text-ink-2" />
                </ReasonRow>
              ))}
            </ul>
          </div>
        ) : null}
      </div>
    </section>
  )
}

function PackageLine({ pkg }: { pkg: PipPackage }) {
  return (
    <p className="flex flex-wrap items-baseline gap-x-1.5">
      <span data-reason-name className="font-semibold text-ink [overflow-wrap:anywhere]">
        {pkg.name}
      </span>
      <span className={cn(mono, "text-ink-2")}>{pkg.version}</span>
    </p>
  )
}

/** The known CVEs a changed pin fixed since the previous crossing. */
function fixedSince(pkg: PipPackage) {
  const now = new Set(pkg.cves.map((cve) => cve.id))
  return (pkg.previous?.cves ?? []).filter((cve) => !now.has(cve.id))
}

/** A row's counts: what a changed pin fixed, else what the package keeps. */
function rowVector(kind: PipGroupKey, pkg: PipPackage): number[] {
  return pipVector(kind === "changed" ? fixedSince(pkg) : pkg.cves)
}

const GROUPS: Record<"changed" | "added" | "fix" | "unchanged" | "packages", { icon: typeof Minus; one: string; many: string; words: string }> = {
  changed: { icon: ArrowUpRight, one: "pin", many: "pins", words: "changed" },
  added: { icon: Plus, one: "package", many: "packages", words: "added" },
  fix: { icon: Shield, one: "package", many: "packages", words: "with a fix in a newer release" },
  unchanged: { icon: Minus, one: "package", many: "packages", words: "unchanged" },
  packages: { icon: Package, one: "package", many: "packages", words: "" },
}

interface GroupProps {
  kind: PipGroupKey
  first: boolean
  packages: PipPackage[]
  open: boolean
  onToggle: () => void
  /** The package whose row explains severities, when this group holds the first one. */
  severityAt?: string
  explainWheel: boolean
}

function Group({ kind, first, packages, open, onToggle, severityAt, explainWheel }: GroupProps) {
  const [all, setAll] = useState(false)
  const look = GROUPS[kind as keyof typeof GROUPS]
  const Icon = look.icon
  const fixed = kind === "changed" ? total(pipVector(packages.flatMap(fixedSince))) : 0
  const left = kind === "fix" ? pipVector(packages.flatMap((pkg) => pkg.cves)) : undefined
  const rows = all ? packages : packages.slice(0, FIRST_ROWS)
  const th = "py-2 pr-3 text-left text-xs font-semibold text-muted"
  let summary: ReactNode = <span className="ml-auto" />
  if (kind === "changed" && fixed > 0) {
    summary = (
      <span className="ml-auto text-[13px] text-muted">
        <span className="figure text-ink">{fixed.toLocaleString("en-US")}</span> {fixed === 1 ? "known CVE fixed" : "known CVEs fixed"}
      </span>
    )
  } else if (left && total(left) > 0) {
    summary = (
      <span className="ml-auto inline-flex items-center gap-1.5 text-[13px] text-muted">
        <SeverityCounts vector={left} /> left
      </span>
    )
  }

  return (
    <div data-group={kind} className={cn(!first && "border-t border-rule")}>
      <button
        type="button"
        aria-expanded={open}
        onClick={onToggle}
        className="flex min-h-14 w-full min-w-0 flex-wrap items-center gap-x-3 gap-y-0.5 px-4 py-2 text-left transition-colors duration-150 [@media(hover:hover)_and_(pointer:fine)]:hover:bg-hover"
      >
        <Icon aria-hidden="true" className="size-4 flex-none text-ink-2" />
        <span className="text-[15px] text-ink-2">
          <span className="figure text-ink">{plural(packages.length, look.one, look.many)}</span>
          {look.words ? ` ${look.words}` : ""}
        </span>
        {summary}
        <ChevronDown aria-hidden="true" className={cn("size-4 flex-none text-muted transition-transform duration-200 ease-out motion-reduce:transition-none", !open && "-rotate-90")} />
      </button>
      {open ? (
        <div className="animate-fade overflow-x-auto px-4 pb-3">
          <table className="w-full min-w-[34rem] text-[13px]">
            <thead>
              <tr className="border-b border-rule">
                <th scope="col" className={th}>Package</th>
                <th scope="col" className={th}>Version</th>
                <th scope="col" className={th}>Pinned in</th>
                <th scope="col" className={th}>{kind === "changed" ? "Known CVEs fixed" : "Known CVEs"}</th>
                <th scope="col" className={cn(th, "pr-0")}>
                  <span className="inline-flex items-center gap-1">
                    Wheel
                    {explainWheel ? <Term id="wheel" /> : null}
                  </span>
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.map((pkg) => {
                const vector = rowVector(kind, pkg)
                const fixes = kind === "changed" ? [] : [...new Set(pkg.cves.flatMap((cve) => cve.fixedVersions.filter((v) => v.trim() !== "")))]
                return (
                  <tr key={pkg.name} className="border-b border-rule last:border-b-0">
                    <td className="py-2 pr-3 align-top font-medium text-ink [overflow-wrap:anywhere]">{pkg.name}</td>
                    <td className="py-2 pr-3 align-top">
                      {kind === "changed" && pkg.previous ? <VersionChange before={pkg.previous.version} after={pkg.version} /> : <span className={cn(mono, "text-ink-2")}>{pkg.version}</span>}
                    </td>
                    <td className="py-2 pr-3 align-top">
                      <PinnedIn pkg={pkg} className="text-ink-2" />
                    </td>
                    <td className="py-2 pr-3 align-top">
                      <span className="inline-flex flex-wrap items-center gap-x-1">
                        <SeverityCounts vector={vector} />
                        {severityAt === pkg.name ? <Term id="severity" /> : null}
                      </span>
                      {fixes.length > 0 ? (
                        <span className="mt-0.5 block text-xs text-muted [overflow-wrap:anywhere]">
                          fixed in <strong className={cn(mono, "font-semibold text-ink")}>{fixes.join(", ")}</strong>
                        </span>
                      ) : null}
                    </td>
                    <td className={cn("py-2 align-top text-ink-2", mono)}>{pkg.wheel ? wheelPlatform(pkg.wheel.file) : "none"}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
          {packages.length > FIRST_ROWS && !all ? (
            <Button type="button" variant="ghost" className="mt-2" onClick={() => setAll(true)}>
              {`Show all ${plural(packages.length, look.one, look.many)}`}
            </Button>
          ) : null}
        </div>
      ) : null}
    </div>
  )
}
