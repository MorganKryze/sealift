import { Check, ChevronDown, ChevronsDown, FilePlus, Files, ShieldCheck, TriangleAlert, Upload } from "lucide-react"
import { useId, useState } from "react"

import { Button } from "@/components/ui/button"
import { formatDbDate } from "@/lib/format-tools"
import type { RequirementsCheck, RequirementsFilePreview, RequirementsLine, RequirementsPreview } from "@/lib/requirementsPreview"
import { cn } from "@/lib/utils"

interface RequirementsBlockProps {
  preview: RequirementsPreview
  /** When the newest file was last changed on the developer's disk. */
  modified?: Date
  /** Offered only where new files can replace these. */
  onReplace?: () => void
  /** Offered where a missing included file can join the set. */
  onAddFiles?: () => void
  /** The files are on their way to the server: Replace and Add file wait. */
  busy?: boolean
}

const FIRST_PINS = 30
const FIRST_LINES = 15

const figure = (n: number) => n.toLocaleString("en-US")
const plural = (n: number, one: string, many: string) => `${figure(n)} ${n === 1 ? one : many}`

/**
 * Requirements files read back, as the package.json's Check block reads one: the newest file's date, the
 * Compliant chip that opens the five checks the server makes, then one row per file that opens its pins. A
 * failing check opens the chip on arrival, one amber row per failure with what to do and each line as written
 * with its file and line.
 */
export function RequirementsBlock({ preview, modified, onReplace, onAddFiles, busy = false }: RequirementsBlockProps) {
  const failing = preview.checks.filter((check) => !check.passed)
  const [checksOpen, setChecksOpen] = useState(failing.length > 0)
  const titleId = useId()
  const when = modified && !Number.isNaN(modified.getTime()) ? formatDbDate(modified.toISOString()) : undefined

  return (
    <div className="rounded-xl border border-rule bg-bg">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2.5 px-4 py-3.5">
        <span className="grid size-10 flex-none place-items-center rounded-lg bg-hover text-ink-2">
          <Files aria-hidden="true" className="size-4.5" />
        </span>
        <div className="min-w-0 flex-1">
          <p className="text-[13px] font-semibold text-ink">{plural(preview.files.length, "requirements file", "requirements files")}</p>
          <p className="text-[13px] text-muted">
            <span className="figure text-ink">{figure(preview.pins)}</span> {preview.pins === 1 ? "pin" : "pins"}
            {when ? (
              <>
                {" · modified "}
                <span className="figure text-ink">{when}</span>
              </>
            ) : null}
          </p>
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
              {`${preview.checks.length} checks passed`}
            </p>
          ) : null}
          <ul aria-labelledby={failing.length === 0 ? titleId : undefined} aria-label={failing.length === 0 ? undefined : "Checks"} className="flex flex-col gap-2">
            {preview.checks.map((check) => (
              <li key={check.id}>
                {check.passed ? <PassedCheck check={check} /> : <FailedCheck check={check} onAddFiles={check.id === "included" ? onAddFiles : undefined} busy={busy} />}
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      <ul aria-label="Requirements files">
        {preview.files.map((file, i) => (
          <li key={file.name} className="border-t border-rule">
            <FileRow file={file} last={i === preview.files.length - 1} />
          </li>
        ))}
      </ul>
    </div>
  )
}

function FileRow({ file, last }: { file: RequirementsFilePreview; last: boolean }) {
  const [open, setOpen] = useState(false)
  const [all, setAll] = useState(false)
  const shown = all ? file.pins : file.pins.slice(0, FIRST_PINS)
  const count = file.constraints > 0 ? plural(file.constraints, "constraint", "constraints") : plural(file.pins.length, "pin", "pins")
  const [figures, ...words] = count.split(" ")
  return (
    <>
      <button
        type="button"
        aria-expanded={open}
        onClick={() => setOpen((was) => !was)}
        className={cn(
          "flex min-h-11 w-full flex-wrap items-center gap-x-2.5 gap-y-0.5 px-4 py-2 text-left transition-colors duration-150 [@media(hover:hover)_and_(pointer:fine)]:hover:bg-hover",
          last && !open && "rounded-b-xl",
        )}
      >
        <ChevronDown aria-hidden="true" className={cn("size-4 flex-none text-muted transition-transform duration-200 ease-out motion-reduce:transition-none", !open && "-rotate-90")} />
        <span className="min-w-0 font-mono text-[13px] text-ink [overflow-wrap:anywhere]">{file.name}</span>
        <span className="text-[13px] text-muted">
          <span className="figure text-ink">{figures}</span> {words.join(" ")}
        </span>
        {file.includes.length > 0 ? (
          <span className="min-w-0 font-mono text-xs text-muted [overflow-wrap:anywhere]">{file.includes.map((inc) => `${inc.option} ${inc.target}`).join(" · ")}</span>
        ) : null}
      </button>
      {open ? (
        <div className="animate-fade px-4 pb-4">
          <ul aria-label={`Pins in ${file.name}`} className="grid grid-cols-1 gap-x-7 sm:grid-cols-3">
            {shown.map((pin, i) => (
              <li key={`${pin.name}:${i}`} className="flex min-h-8 min-w-0 flex-wrap items-baseline justify-between gap-x-3 border-b border-rule py-1.5 text-[13px]">
                <span className="min-w-0 text-ink [overflow-wrap:anywhere]">{pin.name}</span>
                <span className="ml-auto min-w-0 text-right font-mono text-xs text-ink-2 [font-variant-ligatures:none] [overflow-wrap:anywhere]">{pin.version}</span>
              </li>
            ))}
          </ul>
          {shown.length < file.pins.length ? (
            <Button type="button" variant="outline" size="sm" className="mt-3" onClick={() => setAll(true)}>
              <ChevronsDown aria-hidden="true" />
              {`Show all ${figure(file.pins.length)} pins`}
            </Button>
          ) : null}
        </div>
      ) : null}
    </>
  )
}

// "94 of 94 pinned with ==": the count the developer reads for stands out, the rest qualifies it. The options
// seen are data, so they read in monospace.
function Evidence({ check, className }: { check: RequirementsCheck; className?: string }) {
  if (check.id === "options" && check.passed) {
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

function PassedCheck({ check }: { check: RequirementsCheck }) {
  return (
    <div className="grid min-h-8 grid-cols-[16px_minmax(0,1fr)] items-center gap-x-3 sm:grid-cols-[16px_150px_minmax(0,1fr)]">
      <Check aria-hidden="true" className="size-4 text-ok" />
      <span className="text-[13px] font-medium text-ink">{check.label}</span>
      <Evidence check={check} className="col-start-2 sm:col-start-auto" />
    </div>
  )
}

function FailedCheck({ check, onAddFiles, busy }: { check: RequirementsCheck; onAddFiles?: () => void; busy: boolean }) {
  const [all, setAll] = useState(false)
  const shown = all ? check.offenders : check.offenders.slice(0, FIRST_LINES)
  return (
    <div role="group" aria-label={check.label} className="tinted-warn px-3.5 py-3">
      <div className="grid grid-cols-[16px_minmax(0,1fr)] items-center gap-x-3 sm:grid-cols-[16px_150px_minmax(0,1fr)]">
        <TriangleAlert aria-hidden="true" className="size-4 text-warn" />
        <span className="text-[13px] font-semibold text-ink">{check.label}</span>
        <Evidence check={check} className="col-start-2 sm:col-start-auto" />
      </div>
      <p className="mt-1.5 pl-7 text-[13px] text-ink-2">{check.fix}</p>
      <ul className="mt-2 pl-7">
        {shown.map((offender) => (
          <OffendingLine key={`${offender.file}:${offender.line}`} offender={offender} />
        ))}
      </ul>
      {shown.length < check.offenders.length || onAddFiles ? (
        <div className="mt-3 ml-7 flex flex-wrap gap-2">
          {shown.length < check.offenders.length ? (
            <Button type="button" variant="outline" size="sm" onClick={() => setAll(true)}>
              <ChevronsDown aria-hidden="true" />
              {`Show all ${figure(check.offenders.length)} lines`}
            </Button>
          ) : null}
          {onAddFiles ? (
            <Button type="button" variant="outline" size="sm" disabled={busy} onClick={onAddFiles}>
              <FilePlus aria-hidden="true" />
              Add file
            </Button>
          ) : null}
        </div>
      ) : null}
    </div>
  )
}

// The line as written, split where the check names a part: the name, then the part at fault in amber. A line
// with no name to give, such as a URL or an editable install, reads whole.
function OffendingLine({ offender }: { offender: RequirementsLine }) {
  return (
    <li className="grid min-h-8 min-w-0 grid-cols-1 items-baseline gap-x-4 gap-y-0.5 border-b border-warn-line/50 py-1.5 text-[13px] sm:grid-cols-[minmax(0,12rem)_minmax(0,1fr)_auto]">
      {offender.name !== undefined ? (
        <>
          <span className={cn("min-w-0 text-ink [overflow-wrap:anywhere]", offender.name.startsWith("-") && "font-mono text-xs")}>{offender.name}</span>
          <span className="min-w-0 font-mono text-xs font-semibold text-warn [font-variant-ligatures:none] [overflow-wrap:anywhere]">{offender.value}</span>
        </>
      ) : (
        <span className="min-w-0 font-mono text-xs font-semibold text-warn [font-variant-ligatures:none] [overflow-wrap:anywhere] sm:col-span-2">{offender.text}</span>
      )}
      <span className="min-w-0 font-mono text-xs text-muted [overflow-wrap:anywhere] sm:text-right">{`${offender.file}:${offender.line}`}</span>
    </li>
  )
}
