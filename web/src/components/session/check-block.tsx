import { Check, ChevronDown, ChevronsDown, FileJson, ShieldCheck, TriangleAlert, Upload } from "lucide-react"
import { useId, useState } from "react"

import { Button } from "@/components/ui/button"
import { formatDbDate } from "@/lib/format-tools"
import { failingChecks, type ManifestCheck, type ManifestPreview } from "@/lib/manifestPreview"
import { cn } from "@/lib/utils"

interface CheckBlockProps {
  manifest: ManifestPreview
  /** When the file was last changed on the developer's disk; a stored package.json has none. */
  modified?: Date
  /** Offered only where a new file can replace this one. */
  onReplace?: () => void
  /** The file is on its way to the server: Replace waits. */
  busy?: boolean
}

const FIRST_PACKAGES = 30
const FIRST_OFFENDERS = 15

const figure = (n: number) => n.toLocaleString("en-US")
const plural = (n: number, one: string, many: string) => `${figure(n)} ${n === 1 ? one : many}`
const byName = (a: { name: string }, b: { name: string }) => a.name.replace(/^@/, "").localeCompare(b.name.replace(/^@/, ""), "en")

/**
 * The package.json read back: its modified date, the Compliant chip that opens the three checks the server
 * makes, and the package count that opens the packages. Every check passing, both arrive closed; a failing
 * check opens the chip on arrival, one amber row per failure with what to do and each package as written.
 */
export function CheckBlock({ manifest, modified, onReplace, busy = false }: CheckBlockProps) {
  const failing = failingChecks(manifest)
  const [checksOpen, setChecksOpen] = useState(failing.length > 0)
  const [packagesOpen, setPackagesOpen] = useState(false)
  const [allPackages, setAllPackages] = useState(false)
  const titleId = useId()

  const prod = manifest.dependencies.filter((dep) => dep.kind === "prod").length
  const dev = manifest.dependencies.length - prod
  const packages = [...manifest.dependencies].sort(byName)
  const shown = allPackages ? packages : packages.slice(0, FIRST_PACKAGES)
  const when = modified && !Number.isNaN(modified.getTime()) ? formatDbDate(modified.toISOString()) : undefined

  return (
    <div className="rounded-xl border border-rule bg-bg">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2.5 px-4 py-3.5">
        <span className="grid size-10 flex-none place-items-center rounded-lg bg-hover text-ink-2">
          <FileJson aria-hidden="true" className="size-4.5" />
        </span>
        <div className="min-w-0 flex-1">
          <p className="font-mono text-[13px] text-ink">package.json</p>
          {when ? (
            <p className="text-[13px] text-muted">
              modified <span className="figure text-ink">{when}</span>
            </p>
          ) : null}
        </div>
        <div className="flex flex-wrap items-center gap-2 max-sm:basis-full">
          <button
            type="button"
            aria-expanded={checksOpen}
            onClick={() => setChecksOpen((open) => !open)}
            className={cn(
              "inline-flex h-8 items-center gap-1.5 rounded-full px-3 text-[13px] font-semibold transition-[transform] duration-160 ease-out motion-safe:active:scale-[0.97]",
              failing.length === 0 ? "tinted-ok text-ok" : "tinted-warn text-warn",
            )}
          >
            {failing.length === 0 ? <ShieldCheck aria-hidden="true" className="size-4" /> : <TriangleAlert aria-hidden="true" className="size-4" />}
            {failing.length === 0 ? "Compliant" : plural(failing.length, "issue", "issues")}
            <ChevronDown aria-hidden="true" className={cn("size-4 transition-transform duration-200 ease-out motion-reduce:transition-none", checksOpen && "rotate-180")} />
          </button>
          {onReplace ? (
            <Button type="button" variant="ghost" size="sm" disabled={busy} onClick={onReplace}>
              <Upload aria-hidden="true" />
              Replace
            </Button>
          ) : null}
        </div>
      </div>

      {checksOpen ? (
        <div className="animate-fade border-t border-rule px-4 py-3.5">
          {failing.length === 0 ? (
            <p id={titleId} className="mb-1.5 text-xs font-semibold text-muted">
              {`${manifest.checks.length} checks passed`}
            </p>
          ) : null}
          <ul aria-labelledby={failing.length === 0 ? titleId : undefined} aria-label={failing.length === 0 ? undefined : "Checks"} className="flex flex-col gap-2">
            {manifest.checks.map((check) => (
              <li key={check.id}>{check.passed ? <PassedCheck check={check} /> : <FailedCheck check={check} />}</li>
            ))}
          </ul>
        </div>
      ) : null}

      <div className="border-t border-rule">
        <button
          type="button"
          aria-expanded={packagesOpen}
          onClick={() => setPackagesOpen((open) => !open)}
          className="flex min-h-11 w-full flex-wrap items-center gap-x-2.5 gap-y-0.5 rounded-b-xl px-4 py-2 text-left transition-colors duration-150 [@media(hover:hover)_and_(pointer:fine)]:hover:bg-hover"
        >
          <ChevronDown aria-hidden="true" className={cn("size-4 flex-none text-muted transition-transform duration-200 ease-out motion-reduce:transition-none", !packagesOpen && "-rotate-90")} />
          <span className="figure text-ink">{plural(manifest.dependencies.length, "package", "packages")}</span>
          <span className="text-[13px] text-muted">
            {[prod > 0 ? plural(prod, "dependency", "dependencies") : "", dev > 0 ? plural(dev, "devDependency", "devDependencies") : ""].filter(Boolean).join(" · ")}
          </span>
        </button>
        {packagesOpen ? (
          <div className="animate-fade px-4 pb-4">
            <ul aria-label="Packages" className="grid grid-cols-1 gap-x-7 sm:grid-cols-3">
              {shown.map((dep) => (
                <li key={`${dep.kind}:${dep.name}`} className="flex min-h-8 min-w-0 flex-wrap items-baseline justify-between gap-x-3 border-b border-rule py-1.5 text-[13px]">
                  <span className="min-w-0 text-ink [overflow-wrap:anywhere]">{dep.name}</span>
                  <span className="ml-auto min-w-0 text-right font-mono text-xs text-ink-2 [font-variant-ligatures:none] [overflow-wrap:anywhere]">{dep.version}</span>
                </li>
              ))}
            </ul>
            {shown.length < packages.length ? (
              <Button type="button" variant="outline" size="sm" className="mt-3" onClick={() => setAllPackages(true)}>
                <ChevronsDown aria-hidden="true" />
                {`Show all ${figure(packages.length)} packages`}
              </Button>
            ) : null}
          </div>
        ) : null}
      </div>
    </div>
  )
}

// "150 of 150 pinned": the count the developer reads for stands out, the rest qualifies it.
function Evidence({ check, className }: { check: ManifestCheck; className?: string }) {
  if (check.id === "fields" && check.passed) {
    return <span className={cn("min-w-0 font-mono text-xs text-ink-2 [overflow-wrap:anywhere]", className)}>{check.evidence}</span>
  }
  const [, count, rest] = /^([\d,]+)(.*)$/.exec(check.evidence) ?? ["", "", check.evidence]
  return (
    <span className={cn("min-w-0 text-[13px] text-ink-2", className)}>
      <span className={cn("figure", check.passed ? "text-ink" : "text-warn")}>{count}</span>
      {rest}
    </span>
  )
}

function PassedCheck({ check }: { check: ManifestCheck }) {
  return (
    <div className="grid min-h-8 grid-cols-[16px_minmax(0,1fr)] items-center gap-x-3 sm:grid-cols-[16px_150px_minmax(0,1fr)]">
      <Check aria-hidden="true" className="size-4 text-ok" />
      <span className="text-[13px] font-medium text-ink">{check.label}</span>
      <Evidence check={check} className="col-start-2 sm:col-start-auto" />
    </div>
  )
}

function FailedCheck({ check }: { check: ManifestCheck }) {
  const [all, setAll] = useState(false)
  const shown = all ? check.offenders : check.offenders.slice(0, FIRST_OFFENDERS)
  const fields = check.id === "fields"
  const exact = check.id === "exact"
  return (
    <div role="group" aria-label={check.label} className="tinted-warn px-3.5 py-3">
      <div className="grid grid-cols-[16px_minmax(0,1fr)] items-center gap-x-3 sm:grid-cols-[16px_150px_minmax(0,1fr)]">
        <TriangleAlert aria-hidden="true" className="size-4 text-warn" />
        <span className="text-[13px] font-semibold text-ink">{check.label}</span>
        <Evidence check={check} className="col-start-2 sm:col-start-auto" />
      </div>
      <p className="mt-1.5 pl-7 text-[13px] text-ink-2">{check.fix}</p>
      <ul className={cn("mt-2 grid grid-cols-1 gap-x-6 pl-7", exact && "sm:grid-cols-3")}>
        {shown.map((offender) => (
          <li
            key={offender.name}
            className={cn(
              "min-h-8 min-w-0 border-b border-warn-line/50 py-1.5 text-[13px]",
              // A range is short and sits at the row's end; a source or an override list runs long, so it gets its own column.
              exact ? "flex flex-wrap items-baseline justify-between gap-x-3" : "grid grid-cols-1 gap-x-4 gap-y-0.5 sm:grid-cols-[13rem_minmax(0,1fr)]",
            )}
          >
            <span className={cn("min-w-0 text-ink [overflow-wrap:anywhere]", fields && "font-mono text-xs")}>{offender.name}</span>
            <span className={cn("min-w-0 font-mono text-xs font-semibold text-warn [font-variant-ligatures:none] [overflow-wrap:anywhere]", exact && "ml-auto text-right")}>{offender.value}</span>
          </li>
        ))}
      </ul>
      {shown.length < check.offenders.length ? (
        <Button type="button" variant="outline" size="sm" className="mt-3 ml-7" onClick={() => setAll(true)}>
          <ChevronsDown aria-hidden="true" />
          {`Show all ${figure(check.offenders.length)} packages`}
        </Button>
      ) : null}
    </div>
  )
}
