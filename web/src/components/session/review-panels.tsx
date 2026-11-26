import { ArrowRight, ArrowUpRight, Check, Circle, CircleAlert, Diamond, Info, Triangle, Wrench } from "lucide-react"
import { useId, useRef, useState, type KeyboardEvent, type ReactNode } from "react"

import type { DependencyResult } from "@/api/projects"
import { Button } from "@/components/ui/button"
import { Panel } from "@/components/ui/panel"
import { Term } from "@/components/ui/term"
import { MAX_REASON_CHARACTERS, reasonProblem } from "@/lib/requiredReasons"
import { cveFix, cvesOf, distinctCves, type Cve, type Family } from "@/lib/reviewGroups"
import { cn } from "@/lib/utils"

const SEVERITIES = ["critical", "high", "medium", "low", "unknown"] as const
type Severity = (typeof SEVERITIES)[number]

const SEVERITY_LOOK: Record<Severity, { icon: typeof Circle; tone: string; fill: boolean }> = {
  critical: { icon: Diamond, tone: "text-sev-critical", fill: true },
  high: { icon: Triangle, tone: "text-sev-high", fill: true },
  medium: { icon: Circle, tone: "text-sev-medium", fill: true },
  low: { icon: Circle, tone: "text-sev-low", fill: false },
  unknown: { icon: Circle, tone: "text-faint", fill: false },
}

/** A CVE's severity as Trivy prints it, upper case, read as one of the five the counts use. */
export function severityOf(cve: Cve): Severity {
  const word = cve.severity.toLowerCase()
  return (SEVERITIES as readonly string[]).includes(word) ? (word as Severity) : "unknown"
}

/** A severity's shape, word and colour, with a count in front when there is one: "▲ 3 high". */
export function SeverityMark({ severity, count, className }: { severity: Severity; count?: number; className?: string }) {
  const look = SEVERITY_LOOK[severity]
  const Icon = look.icon
  return (
    <span className={cn("inline-flex items-center gap-1 text-[13px] font-medium whitespace-nowrap", look.tone, className)}>
      <Icon aria-hidden="true" className="size-2.5 flex-none" fill={look.fill ? "currentColor" : "none"} strokeWidth={look.fill ? 1 : 2.5} />
      {count === undefined ? severity : `${count.toLocaleString("en-US")} ${severity}`}
    </span>
  )
}

/** The counts of a vector by severity, worst first, or "0" when it holds none. */
export function SeverityCounts({ vector, className }: { vector: number[]; className?: string }) {
  const entries = SEVERITIES.map((severity, index) => ({ severity, count: vector[index] ?? 0 })).filter((entry) => entry.count > 0)
  if (entries.length === 0) {
    return <span className={cn("figure text-[13px] text-muted", className)}>0</span>
  }
  return (
    <span className={cn("inline-flex flex-wrap items-center gap-x-2.5 gap-y-0.5", className)}>
      {entries.map((entry) => (
        <SeverityMark key={entry.severity} severity={entry.severity} count={entry.count} />
      ))}
    </span>
  )
}

/** The vector of a list of CVEs, critical to unknown. */
export function vectorOfCves(cves: Cve[]): number[] {
  const vector = [0, 0, 0, 0, 0]
  for (const cve of cves) vector[SEVERITIES.indexOf(severityOf(cve))] += 1
  return vector
}

/**
 * Before, an arrow, after, in mono: after's unchanged part muted, the rest bold from its first segment that
 * differs (4.17.20 to 4.17.21, 18.3.1 to 19.2.0). A long pair wraps at the arrow.
 */
export function VersionChange({ before, after, marked = true, className }: { before: string; after: string; marked?: boolean; className?: string }) {
  const from = before.split(".")
  const to = after.split(".")
  let same = 0
  while (same < to.length - 1 && to[same] === from[same]) same += 1
  const prefix = same > 0 ? `${to.slice(0, same).join(".")}.` : ""
  return (
    <span
      data-version-change={marked || undefined}
      className={cn("inline-flex min-w-0 flex-wrap items-center gap-x-1.5 font-mono text-[12.5px] [font-variant-ligatures:none]", className)}
    >
      <span className="text-muted [overflow-wrap:anywhere]">{before}</span>
      <ArrowRight aria-hidden="true" className="size-3 flex-none text-muted" />
      <span className="sr-only"> to </span>
      <span className="[overflow-wrap:anywhere]">
        {prefix ? <span className="text-muted">{prefix}</span> : null}
        <strong className="font-semibold text-ink">{after.slice(prefix.length)}</strong>
      </span>
    </span>
  )
}

/** How long ago a version was published, in the largest unit that reads: "128 days", "11 months", "5 years". */
export function releaseAge(published: string | undefined, now: Date = new Date()): string | undefined {
  if (!published) return undefined
  const days = Math.max(0, Math.round((now.getTime() - new Date(published).getTime()) / 86_400_000))
  if (Number.isNaN(days)) return undefined
  const unit = (n: number, word: string) => `${n.toLocaleString("en-US")} ${word}${n === 1 ? "" : "s"}`
  if (days < 60) return unit(days, "day")
  const months = Math.round(days / 30.4)
  if (months < 24) return unit(months, "month")
  return unit(Math.round(months / 12), "year")
}

const CVE_ID = /^CVE-\d{4}-\d{4,}$/
const GHSA_ID = /^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$/

/** The public advisory of a CVE or GitHub id, only for an id of either shape; no address is built from any other text. */
export function advisoryOf(id: string): string | undefined {
  if (CVE_ID.test(id)) return `https://nvd.nist.gov/vuln/detail/${id}`
  if (GHSA_ID.test(id)) return `https://github.com/advisories/${id}`
  return undefined
}

/** A CVE's id, as a link to its advisory when it has one. */
export function CveId({ id, className }: { id: string; className?: string }) {
  const advisory = advisoryOf(id)
  const look = cn("font-mono text-[12.5px] text-ink [font-variant-ligatures:none] [overflow-wrap:anywhere]", className)
  if (!advisory) return <span className={look}>{id}</span>
  return (
    <a href={advisory} target="_blank" rel="noopener noreferrer" className={cn(look, "inline-flex min-h-8 items-center underline decoration-rule-2 hover:decoration-ink")}>
      {id}
    </a>
  )
}

/** What a CVE's record says of its fix, in words. */
export function fixWords(cve: Cve): string {
  const fix = cveFix(cve)
  return fix.kind === "fixed-in" ? `fixed in ${fix.versions}` : fix.kind === "none" ? "No fixed version" : "fix not recorded"
}

/** The line a version belongs to, as a choice names it: "Keep 8", "Jump to 0.25". */
function lineOf(version: string): string {
  const match = /^(\d+)\.(\d+)/.exec(version)
  if (!match) return version
  return match[1] === "0" ? `0.${match[2]}` : match[1]
}

/** Two choices or fewer, one or two words each, as radios with arrow keys. */
function Segmented<T extends string>({ label, value, options, onChange }: { label: string; value: T; options: { value: T; label: string }[]; onChange: (value: T) => void }) {
  const refs = useRef<(HTMLButtonElement | null)[]>([])
  const move = (event: KeyboardEvent, index: number) => {
    const step = event.key === "ArrowRight" || event.key === "ArrowDown" ? 1 : event.key === "ArrowLeft" || event.key === "ArrowUp" ? -1 : 0
    if (step === 0) return
    event.preventDefault()
    const next = (index + step + options.length) % options.length
    onChange(options[next].value)
    refs.current[next]?.focus()
  }
  return (
    <div role="radiogroup" aria-label={label} className="inline-flex rounded-lg border border-rule-2 bg-hover p-0.5">
      {options.map((option, index) => {
        const on = option.value === value
        return (
          <button
            key={option.value}
            ref={(element) => {
              refs.current[index] = element
            }}
            type="button"
            role="radio"
            aria-checked={on}
            tabIndex={on ? 0 : -1}
            onKeyDown={(event) => move(event, index)}
            onClick={() => onChange(option.value)}
            className={cn(
              "inline-flex h-9 items-center gap-1.5 rounded-md px-3.5 text-sm transition-[background-color,color] duration-150",
              on ? "bg-seg-on font-semibold text-ink shadow-[0_1px_2px_rgba(var(--shadow),0.12)]" : "text-ink-2 [@media(hover:hover)_and_(pointer:fine)]:hover:text-ink",
            )}
          >
            {on ? <Check aria-hidden="true" className="size-4" /> : null}
            {option.label}
          </button>
        )
      })}
    </div>
  )
}

/** The reason field of a panel, with its count near the limit and its problem in words. */
function ReasonField({ value, onChange, help }: { value: string; onChange: (text: string) => void; help: string }) {
  const id = useId()
  const problem = reasonProblem(value)
  const length = [...value.trim()].length
  return (
    <div className="mt-5 flex flex-col gap-1.5">
      <label htmlFor={id} className="text-[13px] font-semibold text-ink">
        Reason <span className="font-normal text-muted">required</span>
      </label>
      <textarea
        id={id}
        rows={3}
        value={value}
        spellCheck
        aria-invalid={problem !== undefined}
        aria-describedby={`${id}-help`}
        // A reason is one line: Enter adds nothing, and a pasted line break shows its problem.
        onKeyDown={(event) => {
          if (event.key === "Enter") event.preventDefault()
        }}
        onChange={(event) => onChange(event.target.value)}
        className={cn(
          "min-h-18 w-full resize-y rounded-lg border bg-bg px-3 py-2 text-sm text-ink outline-none transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ink",
          problem ? "border-bad" : "border-field",
        )}
      />
      <p id={`${id}-help`} className="text-[13px] text-muted">
        {help}
        {length >= MAX_REASON_CHARACTERS - 60 ? (
          <span className="figure ml-2 text-ink-2">{`${length} of ${MAX_REASON_CHARACTERS} characters`}</span>
        ) : null}
      </p>
    </div>
  )
}

/** Record at the left after the content, its cause above it while it waits. */
function RecordAction({ cause, onRecord }: { cause?: string; onRecord: () => void }) {
  const id = useId()
  return (
    <div className="mt-5 flex flex-col items-start gap-2">
      {cause ? (
        <p id={id} className="text-[13px] text-muted">
          {cause}
        </p>
      ) : null}
      <Button
        type="button"
        size="page"
        aria-disabled={cause ? true : undefined}
        aria-describedby={cause ? id : undefined}
        onClick={() => {
          if (!cause) onRecord()
        }}
      >
        <Check aria-hidden="true" />
        Record
      </Button>
    </div>
  )
}

/** Why Record waits for a reason: missing, or one the archive would refuse. */
function reasonCause(text: string): string | undefined {
  if (text.trim() === "") return "Write a reason to record."
  return reasonProblem(text)
}

function Fact({ label, children, className }: { label: string; children: ReactNode; className?: string }) {
  return (
    <div className={cn("min-w-0 px-3.5 py-3", className)}>
      <p className="text-xs font-semibold text-muted">{label}</p>
      <div className="mt-0.5 text-[13px] text-ink">{children}</div>
    </div>
  )
}

const help = "Signed with the archive and read at import."

interface DecidePanelProps {
  dependency: DependencyResult
  /** The version the selection holds, the current one by default. */
  version?: string
  dev: boolean
  reason: string
  onRecord: (choice: { carry: true; reason: string } | { carry: false }) => void
  onClose: () => void
}

/**
 * The decision on a package that keeps a CVE no version fixes: carry it with a reason, or leave it out of
 * the archive, which asks none.
 */
export function DecidePanel({ dependency, version, dev, reason, onRecord, onClose }: DecidePanelProps) {
  const held = version ?? dependency.current
  const [choice, setChoice] = useState<"carry" | "leave">("carry")
  const [text, setText] = useState(reason)
  const cves = distinctCves(cvesOf(dependency, held)).filter((cve) => cveFix(cve).kind !== "fixed-in")
  const newest = newestOf(dependency)
  const cause = choice === "carry" ? reasonCause(text) : undefined

  return (
    <Panel open onClose={onClose} tone="warn" heading="Decision" icon={CircleAlert}>
      <p className="flex flex-wrap items-baseline gap-x-2 text-[22px] font-semibold tracking-tight text-ink">
        <span className="[overflow-wrap:anywhere]">{dependency.name}</span>
        <span className="font-mono text-base font-normal text-muted [font-variant-ligatures:none] [overflow-wrap:anywhere]">{held}</span>
      </p>
      <div className="mt-2.5 flex flex-wrap items-center gap-2">
        <SeverityCounts vector={vectorOfCves(cves)} />
        {dev ? (
          <span className="inline-flex h-7 items-center gap-1.5 rounded-full border border-rule-2 px-2.5 text-[13px] text-ink-2">
            <Wrench aria-hidden="true" className="size-3.5" />
            Dev dependency
          </span>
        ) : null}
      </div>

      <div className="mt-4 rounded-xl border border-rule">
        <div className="px-3.5 pt-3">
          <p className="flex items-center gap-1 text-xs font-semibold text-muted">
            Known CVEs
            <Term id="cve" />
          </p>
          <ul className="mt-1 flex flex-col">
            {cves.map((cve) => (
              <li key={cve.id} className="flex min-h-8 flex-wrap items-center gap-x-3 border-t border-rule py-1 first:border-t-0">
                <CveId id={cve.id} />
                <SeverityMark severity={severityOf(cve)} />
                <span className="text-[13px] text-muted">{fixWords(cve)}</span>
              </li>
            ))}
          </ul>
        </div>
        <Fact label="Newest version" className="border-t border-rule">
          <span className="font-mono [font-variant-ligatures:none] [overflow-wrap:anywhere]">{newest}</span>
          {newest === held ? <span>, this one</span> : null}
        </Fact>
      </div>

      <div className="mt-5">
        <Segmented
          label={`What to do with ${dependency.name}`}
          value={choice}
          onChange={setChoice}
          options={[
            { value: "carry", label: "Carry" },
            { value: "leave", label: "Leave out" },
          ]}
        />
      </div>
      {choice === "carry" ? (
        <ReasonField value={text} onChange={setText} help={help} />
      ) : (
        <p className="mt-4 text-[13px] text-ink-2">{`The archive will not carry ${dependency.name}.`}</p>
      )}
      <RecordAction cause={cause} onRecord={() => onRecord(choice === "carry" ? { carry: true, reason: text.trim() } : { carry: false })} />
    </Panel>
  )
}

/** The highest version the analysis lists for a dependency, its current one when it lists none higher. */
function newestOf(dependency: DependencyResult): string {
  const parts = (version: string) => {
    const [core, pre] = version.split(/-(.*)/s, 2)
    return { numbers: core.split(".").map((n) => Number.parseInt(n, 10) || 0), pre: pre ?? "" }
  }
  const higher = (a: string, b: string) => {
    const x = parts(a)
    const y = parts(b)
    for (let i = 0; i < Math.max(x.numbers.length, y.numbers.length); i++) {
      const d = (x.numbers[i] ?? 0) - (y.numbers[i] ?? 0)
      if (d !== 0) return d > 0
    }
    // A release ranks above its own pre-releases.
    if (x.pre === "" || y.pre === "") return x.pre === "" && y.pre !== ""
    return x.pre.localeCompare(y.pre, "en", { numeric: true }) > 0
  }
  return dependency.candidates.reduce((best, candidate) => (higher(candidate.version, best) ? candidate.version : best), dependency.current)
}

interface JumpPanelProps {
  dependency: DependencyResult
  family?: Family
  /** The family's dependencies, the one pressed among them; the dependency alone when there is no family. */
  members?: DependencyResult[]
  reason: string
  onRecord: (choice: { jump: true; reason: string } | { jump: false }) => void
  onClose: () => void
}

/** A major jump the analysis recorded: keep the current line, or take the next major with a reason. A family moves as one. */
export function JumpPanel({ dependency, family, members, reason, onRecord, onClose }: JumpPanelProps) {
  const [choice, setChoice] = useState<"keep" | "jump">("jump")
  const [text, setText] = useState(reason)
  const moving = (members && members.length > 0 ? members : [dependency]).filter((d) => d.jump)
  const jumpOf = (d: DependencyResult) => d.candidates.find((c) => c.version === d.jump)
  const sum = (vectors: number[][]) => vectors.reduce((t, v) => t.map((n, i) => n + (v[i] ?? 0)), [0, 0, 0, 0, 0])
  const now = sum(moving.map((d) => d.vector))
  const after = sum(moving.map((d) => jumpOf(d)?.vector ?? d.vector))
  const total = (v: number[]) => v.reduce((a, b) => a + b, 0)
  // A publisher change is the one signal a jump shows as a fact; the jump itself is the panel.
  const signals = moving.flatMap((d) => (jumpOf(d)?.signals ?? []).filter((s) => s.name === "publisher-changed").map((s) => ({ name: d.name, signal: s })))
  const cause = choice === "jump" ? reasonCause(text) : undefined
  const age = releaseAge(jumpOf(dependency)?.published)

  return (
    <Panel open onClose={onClose} tone="info" heading="Major jump" icon={ArrowUpRight}>
      {family ? (
        <div data-version-change className="flex flex-wrap items-center gap-x-2">
          <p className="text-[22px] font-semibold tracking-tight text-ink [overflow-wrap:anywhere]">{family.name}</p>
          <span className="text-[15px] text-muted">{`${moving.length} packages that move together`}</span>
          <Term id="major-jump" />
        </div>
      ) : (
        <div data-version-change className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <p className="text-[22px] font-semibold tracking-tight text-ink [overflow-wrap:anywhere]">{dependency.name}</p>
          <VersionChange before={dependency.current} after={dependency.jump ?? dependency.current} marked={false} className="text-[15px]" />
          <Term id="major-jump" />
        </div>
      )}

      {family ? (
        <div className="mt-4 rounded-xl border border-rule px-3.5 py-1">
          <table className="w-full text-[13px]">
            <thead>
              <tr className="text-left text-xs text-muted">
                <th scope="col" className="py-2 font-semibold">Package</th>
                <th scope="col" className="py-2 font-semibold">Kept to next major</th>
                <th scope="col" className="py-2 text-right font-semibold">Age</th>
              </tr>
            </thead>
            <tbody>
              {moving.map((d) => (
                <tr key={d.name} className="border-t border-rule">
                  <td className="py-2 pr-3 font-medium text-ink [overflow-wrap:anywhere]">{d.name}</td>
                  <td className="py-2 pr-3">
                    <VersionChange before={d.current} after={d.jump ?? d.current} />
                  </td>
                  <td className="py-2 text-right whitespace-nowrap text-ink-2">{releaseAge(jumpOf(d)?.published) ?? "no date"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      <div className="mt-4 grid grid-cols-1 rounded-xl border border-rule sm:grid-cols-2">
        {family ? null : <Fact label="Release age">{age ? <span className="figure">{age}</span> : "no date"}</Fact>}
        <Fact label="Known CVEs" className={family ? "sm:col-span-2" : "border-rule max-sm:border-t sm:border-l"}>
          <span className="inline-flex flex-wrap items-center gap-x-1.5">
            {total(now) === 0 ? <span className="figure">0</span> : <SeverityCounts vector={now} />}
            <ArrowRight aria-hidden="true" className="size-3 text-muted" />
            <span className="sr-only"> to </span>
            {total(after) === 0 ? <span className="figure">0</span> : <SeverityCounts vector={after} />}
          </span>
        </Fact>
        {signals.map(({ name, signal }) => (
          <Fact key={`${name}:${signal.name}`} label={family ? name : "Signal"} className="border-t border-rule sm:col-span-2">
            <span className="inline-flex items-start gap-1.5">
              <Info aria-hidden="true" className="mt-0.5 size-3.5 flex-none text-muted" />
              <span className="[overflow-wrap:anywhere]">{signal.evidence}</span>
            </span>
          </Fact>
        ))}
      </div>

      <div className="mt-5">
        <Segmented
          label={`What to do with ${family?.name ?? dependency.name}`}
          value={choice}
          onChange={setChoice}
          options={[
            { value: "keep", label: `Keep ${lineOf(dependency.current)}` },
            { value: "jump", label: `Jump to ${lineOf(dependency.jump ?? dependency.current)}` },
          ]}
        />
      </div>
      {choice === "jump" ? <ReasonField value={text} onChange={setText} help={help} /> : null}
      <RecordAction cause={cause} onRecord={() => onRecord(choice === "jump" ? { jump: true, reason: text.trim() } : { jump: false })} />
    </Panel>
  )
}

