import { ArrowUpRight, ChevronDown, ChevronRight, CircleAlert, PencilLine } from "lucide-react"
import { useId, useState, type ReactNode } from "react"

import type { AnalysisResult, DependencyResult } from "@/api/projects"
import { SeverityCounts, SeverityMark, VersionChange, fixWords, severityOf, vectorOfCves } from "@/components/session/review-panels"
import { Button } from "@/components/ui/button"
import { Term } from "@/components/ui/term"
import { reasonKey, reasonProblem, type NeededReason } from "@/lib/requiredReasons"
import { cveFix, cvesOf, distinctCves, type Cve } from "@/lib/reviewGroups"
import { cn } from "@/lib/utils"

interface ReasonsBlockProps {
  needed: NeededReason[]
  reasons: Record<string, string>
  result: AnalysisResult
  /** Opens Decide for a dependency that keeps a CVE with no known fix. */
  onDecide: (name: string) => void
  /** Opens Jump for a dependency, or a member of the family, whose jump the selection takes. */
  onJump: (name: string) => void
  /** The server's words when it refused the export for its reasons. */
  refusal?: string
  /** False on Ready, whose head explains CVE and the severities first. */
  explainCves?: boolean
}

const plural = (n: number, one: string, many: string) => `${n.toLocaleString("en-US")} ${n === 1 ? one : many}`

/** A written reason the archive accepts; an empty or refused one still waits. */
function written(text: string | undefined): boolean {
  return text !== undefined && text.trim() !== "" && reasonProblem(text) === undefined
}

interface JumpRow {
  need: NeededReason
  family: boolean
  moves: { dependency: DependencyResult; to: string }[]
}

interface CveRow {
  need: NeededReason
  dependency: DependencyResult
  versions: string[]
  cves: Cve[]
}

// requiredReasons words each move "<name> <from> to <to>" and each kept CVE "<name> <version> keeps <ids>":
// the versions a row holds are the ones its own detail names.
function jumpRow(need: NeededReason, byName: Map<string, DependencyResult>): JumpRow {
  const moves = need.dependencies.flatMap((name) => {
    const dependency = byName.get(name)
    if (!dependency) return []
    const to = [dependency.jump, ...dependency.candidates.map((c) => c.version)].find((v) => v && need.detail.includes(`${name} ${dependency.current} to ${v}`))
    return [{ dependency, to: to ?? dependency.jump ?? dependency.current }]
  })
  const family = moves.some((move) => move.dependency.family === need.label)
  return { need, family, moves }
}

function cveRow(need: NeededReason, byName: Map<string, DependencyResult>): CveRow | undefined {
  const dependency = byName.get(need.dependencies[0])
  if (!dependency) return undefined
  const named = [dependency.current, ...dependency.candidates.map((c) => c.version)].filter((v) => need.detail.includes(`${dependency.name} ${v} keeps `))
  const versions = named.length > 0 ? [...new Set(named)] : [dependency.current]
  const cves = distinctCves(versions.flatMap((v) => cvesOf(dependency, v))).filter((cve) => cveFix(cve).kind !== "fixed-in")
  return { need, dependency, versions, cves }
}

/**
 * What a selection needs a reason for, before the groups: a band of major jumps, a family moving together
 * on one row, then a band of known CVEs with no fixed version, a package per row. A row whose reason is
 * missing is a closed amber row with its action; a written one shows its text. CVE, a severity and major
 * jump are explained once each, at the bands' heads and the first row with severities.
 */
export function ReasonsBlock({ needed, reasons, result, onDecide, onJump, refusal, explainCves = true }: ReasonsBlockProps) {
  const id = useId()
  if (needed.length === 0 && !refusal) {
    return null
  }
  const byName = new Map(result.dependencies.map((d) => [d.name, d]))
  const jumps = needed.filter((n) => n.kind === "major-jump").map((n) => jumpRow(n, byName))
  const cves = needed.filter((n) => n.kind === "cve-without-fix").flatMap((n) => cveRow(n, byName) ?? [])
  const textOf = (need: NeededReason) => reasons[reasonKey(need)]

  const moves = jumps.reduce((sum, row) => sum + row.moves.length, 0)
  const families = jumps.filter((row) => row.family).length
  const jumpsWritten = jumps.filter((row) => written(textOf(row.need))).length
  const cveCount = cves.reduce((sum, row) => sum + row.cves.length, 0)
  const cvesWritten = cves.filter((row) => written(textOf(row.need))).length
  const unknown = cves.some((row) => row.cves.some((cve) => cveFix(cve).kind === "unknown"))
  const carried = (n: number) => (n > 0 ? `, carried with ${plural(n, "reason", "reasons")}` : "")
  const firstSeverities = explainCves ? cves.find((row) => row.cves.length > 0) : undefined

  return (
    <section aria-label="Reasons" className="mb-3">
      {needed.length > 0 ? (
        <div className="overflow-hidden rounded-xl border border-rule bg-bg">
          {jumps.length > 0 ? (
            <div role="group" aria-labelledby={`${id}-jumps`}>
              <ReasonBand tone="info">
                <ArrowUpRight aria-hidden="true" className="size-4 flex-none text-info" />
                <p id={`${id}-jumps`} className="text-[13px] text-ink-2">
                  <span className="figure text-ink">{plural(moves, "major jump", "major jumps")}</span>
                  {families > 0 && families === jumps.length ? ` in ${plural(families, "family", "families")}` : ""}
                  {carried(jumpsWritten)}
                </p>
                <Term id="major-jump" />
              </ReasonBand>
              <ul className="flex flex-col gap-1.5 p-1.5">
                {jumps.map((row) => (
                  <JumpReasonRow key={reasonKey(row.need)} row={row} text={textOf(row.need)} onJump={onJump} />
                ))}
              </ul>
            </div>
          ) : null}
          {cves.length > 0 ? (
            <div role="group" aria-labelledby={`${id}-cves`} className={cn(jumps.length > 0 && "border-t border-rule")}>
              <ReasonBand tone="warn">
                <CircleAlert aria-hidden="true" className="size-4 flex-none text-warn" />
                <p id={`${id}-cves`} className="text-[13px] text-ink-2">
                  <span className="figure text-ink">{plural(cveCount, "known CVE", "known CVEs")}</span>
                  {unknown ? " with no fixed version on record" : " with no fixed version"}
                  {cves.length > 1 ? ` in ${plural(cves.length, "package", "packages")}` : ""}
                  {carried(cvesWritten)}
                </p>
                {explainCves ? <Term id="cve" /> : null}
              </ReasonBand>
              <ul className="flex flex-col gap-1.5 p-1.5">
                {cves.map((row) => (
                  <CveReasonRow key={reasonKey(row.need)} row={row} text={textOf(row.need)} explain={row === firstSeverities} onDecide={onDecide} />
                ))}
              </ul>
            </div>
          ) : null}
        </div>
      ) : null}
      {refusal ? (
        <div role="alert" className="tinted-bad mt-3 px-4 py-3 text-[13px] text-ink">
          <p className="font-semibold">The server refused these reasons</p>
          <p className="text-ink-2 [overflow-wrap:anywhere]">{refusal}</p>
        </div>
      ) : null}
    </section>
  )
}

/** A band's head: its icon, its count and the reasons carried, on the info or warn tint. */
export function ReasonBand({ tone, children }: { tone: "info" | "warn"; children: ReactNode }) {
  return (
    <div className={cn("flex min-h-11 items-center gap-2.5 border-b px-4 py-1", tone === "info" ? "border-info-line/60 bg-info-tint" : "border-warn-line/60 bg-warn-tint")}>
      {children}
    </div>
  )
}

/** A row's reason, or the mark that it is missing; its action, Change once written. */
function ReasonCell({ text, label, action, onAction }: { text?: string; label: string; action: "Decide" | "Jump"; onAction: () => void }) {
  const done = written(text)
  const word = done ? "Change" : action
  return (
    <>
      <div className="min-w-0 sm:border-l sm:border-rule sm:pl-3">
        {done ? (
          <p className="text-[13px] text-ink [overflow-wrap:anywhere]">{`“${(text ?? "").trim()}”`}</p>
        ) : (
          <span className="inline-flex h-6 items-center gap-1.5 rounded-full border border-warn-line bg-bg px-2.5 text-xs font-semibold text-warn">
            <PencilLine aria-hidden="true" className="size-3" />
            {text && text.trim() !== "" ? "Reason to fix" : "Reason missing"}
          </span>
        )}
      </div>
      <Button type="button" variant="outline" aria-label={`${word} ${label}`} data-reason-action={label} onClick={onAction} className="justify-self-start sm:justify-self-end">
        {done ? <PencilLine aria-hidden="true" /> : <ChevronRight aria-hidden="true" />}
        {word}
      </Button>
    </>
  )
}

function Disclosure({ open, label, onToggle }: { open: boolean; label: string; onToggle: () => void }) {
  return (
    <button
      type="button"
      aria-expanded={open}
      aria-label={label}
      onClick={onToggle}
      className="grid size-8 place-items-center rounded-lg text-muted transition-colors duration-150 [@media(hover:hover)_and_(pointer:fine)]:hover:bg-hover [@media(hover:hover)_and_(pointer:fine)]:hover:text-ink"
    >
      <ChevronDown aria-hidden="true" className={cn("size-4 transition-transform duration-200 ease-out motion-reduce:transition-none", !open && "-rotate-90")} />
    </button>
  )
}

const ROW = "grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-3 gap-y-2 px-3 py-2.5 sm:grid-cols-[minmax(0,15rem)_minmax(0,1fr)_auto_2rem]"

interface ReasonRowProps {
  /** The reason's text as written, absent until it is. */
  text?: string
  /** The name its action and focus return use: the package, or the family. */
  label: string
  action: "Decide" | "Jump"
  onAction: () => void
  /** What the row is about: its name, its version and its evidence. */
  children: ReactNode
  /** A chevron that lists the row's detail in place, with what it lists. */
  more?: { label: string; content: ReactNode; ruled?: boolean }
}

/** One row of a band: a closed amber row while its reason is missing, its text and Change once written. */
export function ReasonRow({ text, label, action, onAction, children, more }: ReasonRowProps) {
  const [open, setOpen] = useState(false)
  const missing = !written(text)
  return (
    <li data-reason-row className={cn(missing ? "tinted-warn" : "rounded-lg")}>
      <div className={ROW}>
        <div className="min-w-0">{children}</div>
        <ReasonCell text={text} label={label} action={action} onAction={onAction} />
        {more ? <Disclosure open={open} label={more.label} onToggle={() => setOpen((was) => !was)} /> : <span />}
      </div>
      {open && more ? <div className={cn("animate-fade px-3 pb-2.5", more.ruled && "border-t border-warn-line/50")}>{more.content}</div> : null}
    </li>
  )
}

function JumpReasonRow({ row, text, onJump }: { row: JumpRow; text?: string; onJump: (name: string) => void }) {
  const first = row.moves[0]
  return (
    <ReasonRow
      text={text}
      label={row.need.label}
      action="Jump"
      onAction={() => onJump(row.need.dependencies[0])}
      more={
        row.family
          ? {
              label: `${plural(row.moves.length, "package", "packages")} of ${row.need.label}`,
              content: (
                <table className="w-full text-[13px]">
                  <thead>
                    <tr className="text-left text-xs text-muted">
                      <th scope="col" className="py-1.5 font-semibold">Package</th>
                      <th scope="col" className="py-1.5 font-semibold">Version</th>
                    </tr>
                  </thead>
                  <tbody>
                    {row.moves.map((move) => (
                      <tr key={move.dependency.name} className="border-t border-rule">
                        <td className="py-2 pr-3 font-medium text-ink [overflow-wrap:anywhere]">{move.dependency.name}</td>
                        <td className="py-2">
                          <VersionChange before={move.dependency.current} after={move.to} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ),
            }
          : undefined
      }
    >
      <p data-reason-name className="font-semibold text-ink [overflow-wrap:anywhere]">
        {row.need.label}
      </p>
      {row.family ? (
        <p className="text-[13px] text-muted">{plural(row.moves.length, "package", "packages")}</p>
      ) : first ? (
        <VersionChange before={first.dependency.current} after={first.to} />
      ) : null}
    </ReasonRow>
  )
}

/** The CVEs of a row, listed in place under it: id, severity and what its record says of a fix. */
export function CveTable({ cves }: { cves: Cve[] }) {
  return (
    <table className="w-full text-[13px]">
      <thead>
        <tr className="text-left text-xs text-muted">
          <th scope="col" className="py-1.5 font-semibold">Known CVE</th>
          <th scope="col" className="py-1.5 font-semibold">Severity</th>
          <th scope="col" className="py-1.5 font-semibold">Fix</th>
        </tr>
      </thead>
      <tbody>
        {cves.map((cve) => (
          <tr key={cve.id} className="border-t border-rule">
            <td className="py-1.5 pr-3">
              <span className="font-mono text-xs text-ink [font-variant-ligatures:none] [overflow-wrap:anywhere]">{cve.id}</span>
            </td>
            <td className="py-1.5 pr-3">
              <SeverityMark severity={severityOf(cve)} />
            </td>
            <td className="py-1.5 text-ink-2">{fixWords(cve)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function CveReasonRow({ row, text, explain, onDecide }: { row: CveRow; text?: string; explain: boolean; onDecide: (name: string) => void }) {
  const single = row.cves.length === 1 ? row.cves[0] : undefined
  return (
    <ReasonRow
      text={text}
      label={row.dependency.name}
      action="Decide"
      onAction={() => onDecide(row.dependency.name)}
      more={single ? undefined : { label: `${plural(row.cves.length, "CVE", "CVEs")} of ${row.dependency.name}`, content: <CveTable cves={row.cves} />, ruled: true }}
    >
      <p className="flex flex-wrap items-baseline gap-x-1.5">
        <span data-reason-name className="font-semibold text-ink [overflow-wrap:anywhere]">
          {row.dependency.name}
        </span>
        {row.versions.map((version) => (
          <span key={version} className="font-mono text-[12.5px] text-ink-2 [font-variant-ligatures:none] [overflow-wrap:anywhere]">
            {version}
          </span>
        ))}
      </p>
      <div className="flex flex-wrap items-center gap-x-2">
        {single ? (
          <>
            <span className="font-mono text-xs text-ink-2 [font-variant-ligatures:none] [overflow-wrap:anywhere]">{single.id}</span>
            <SeverityMark severity={severityOf(single)} />
            {cveFix(single).kind === "unknown" ? <span className="text-xs text-muted">fix not recorded</span> : null}
          </>
        ) : (
          <SeverityCounts vector={vectorOfCves(row.cves)} />
        )}
        {explain ? <Term id="severity" /> : null}
      </div>
    </ReasonRow>
  )
}
