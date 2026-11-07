import { CircleAlert, CircleCheck, CircleDashed, CircleQuestionMark, CirclePause, Equal, type LucideIcon } from "lucide-react"
import { useLayoutEffect, useRef, useState } from "react"

import { cn } from "@/lib/utils"
import { nextAction } from "@/import/lib/kinds"
import { counts, notFinished, type Attempt, type ReportPackage } from "@/import/lib/outcome"

import { CopyControl } from "./copy-control"

const PAGE = 100

type Filter = "all" | "failed"
type Row = "published" | "present" | "failed" | "not-finished" | "pending" | "unknown"

const ROW: Record<Row, { label: string; icon: LucideIcon; tone: string }> = {
  published: { label: "Published", icon: CircleCheck, tone: "text-severity-resolved-fg" },
  present: { label: "Present", icon: Equal, tone: "text-muted" },
  failed: { label: "Failed", icon: CircleAlert, tone: "text-severity-critical-fg" },
  "not-finished": { label: "Not finished", icon: CirclePause, tone: "text-severity-high" },
  pending: { label: "Pending", icon: CircleDashed, tone: "text-muted" },
  unknown: { label: "Not recorded", icon: CircleQuestionMark, tone: "text-muted" },
}

function rowOf(p: ReportPackage): Row {
  if (p.state === "failed") {
    return notFinished(p) ? "not-finished" : "failed"
  }
  return p.state === "published" || p.state === "present" || p.state === "pending" ? p.state : "unknown"
}

function Reason({ id, reason }: { id: string; reason: string }) {
  const [open, setOpen] = useState(false)
  const [cut, setCut] = useState(false)
  const clamped = useRef<HTMLParagraphElement>(null)

  useLayoutEffect(() => {
    const el = clamped.current
    if (!el) {
      return
    }
    const measure = () => setCut(el.scrollHeight > el.clientHeight + 1)
    measure()
    if (typeof ResizeObserver === "undefined") {
      return
    }
    const watch = new ResizeObserver(measure)
    watch.observe(el)
    return () => watch.disconnect()
  }, [reason, open])

  return (
    <div className="mt-1">
      {open ? (
        <div className="grid gap-2">
          <div
            role="region"
            aria-label={`Full reason of ${id}`}
            tabIndex={0}
            className="max-h-40 overflow-auto rounded-md border border-line bg-background p-2.5 font-mono text-xs whitespace-pre-wrap [overflow-wrap:anywhere] outline-none focus-visible:ring-2 focus-visible:ring-accent"
          >
            {reason}
          </div>
          <CopyControl text={reason} label={`reason of ${id}`} />
        </div>
      ) : (
        <p ref={clamped} className="line-clamp-2 text-[13px] [overflow-wrap:anywhere]">
          {reason}
        </p>
      )}
      {cut || open ? (
        <button
          type="button"
          aria-expanded={open}
          aria-label={`${open ? "Hide" : "Show"} full reason of ${id}`}
          onClick={() => setOpen(!open)}
          className="mt-1 inline-flex h-8 items-center rounded-md text-sm text-accent underline outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          {open ? "Hide full reason" : "Show full reason"}
        </button>
      ) : null}
    </div>
  )
}

function PackageRow({ p }: { p: ReportPackage }) {
  const kind = rowOf(p)
  const { label, icon: Icon, tone } = ROW[kind]
  const id = `${p.name}@${p.version}`
  const failed = kind === "failed" || kind === "not-finished"
  return (
    <tr className={cn("border-t border-line align-top", kind === "failed" && "bg-severity-critical/10", kind === "not-finished" && "bg-severity-high/10")}>
      <td className="px-3.5 py-2.5 font-mono text-[13px] [overflow-wrap:anywhere]">{id}</td>
      <td className="px-3.5 py-2.5">
        <span className="inline-flex h-6 items-center gap-1.5 text-[13px] font-semibold">
          <Icon aria-hidden className={cn("size-4 shrink-0", tone)} />
          {label}
        </span>
      </td>
      <td className="min-w-0 px-3.5 py-2.5">
        {kind === "present" && p.note ? <p className="text-[13px] text-muted [overflow-wrap:anywhere]">{p.note}</p> : null}
        {failed ? (
          <>
            <Reason id={id} reason={p.reason || "Reason not recorded"} />
            <p className="mt-1 text-[13px]">
              <b className="font-semibold">Next:</b> {nextAction(kind === "not-finished" ? "interrupted" : p.kind).words}
            </p>
          </>
        ) : null}
      </td>
    </tr>
  )
}

const choice = "inline-flex h-8 items-center gap-1.5 rounded-md px-3 text-sm outline-none focus-visible:ring-2 focus-visible:ring-accent"

/**
 * Every package of one attempt. The filter opens on Failed when a package failed and keeps the
 * user's choice across refetches: mount it once per attempt shown. An attempt followed live remounts
 * once when it ends, so the filter opens on what the finished report holds.
 */
export function ReportList({ attempt }: { attempt: Attempt }) {
  return <Packages key={attempt.status === "ended" ? "ended" : "live"} attempt={attempt} />
}

function Packages({ attempt }: { attempt: Attempt }) {
  const c = counts(attempt)
  const failures = c.failed + c.notFinished
  const [filter, setFilter] = useState<Filter>(failures > 0 ? "failed" : "all")
  const [all, setAll] = useState(false)

  const packages = attempt.report.packages
  const shown = filter === "failed" ? packages.filter((p) => p.state === "failed") : packages
  const visible = all ? shown : shown.slice(0, PAGE)
  const options: { id: Filter; label: string; count: number }[] = [
    { id: "all", label: "All", count: c.total },
    { id: "failed", label: "Failed", count: failures },
  ]

  if (packages.length === 0) {
    return <p className="text-sm text-muted">No package is listed for this attempt.</p>
  }
  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-x-4 gap-y-2">
        <div role="group" aria-label="Show packages" className="inline-flex gap-0.5 rounded-lg border border-line bg-card p-0.5">
          {options.map((o) => (
            <button
              key={o.id}
              type="button"
              aria-pressed={filter === o.id}
              onClick={() => setFilter(o.id)}
              className={cn(choice, filter === o.id ? "bg-background font-medium text-ink shadow-sm" : "text-muted hover:text-ink")}
            >
              {`${o.label} ${o.count}`}
            </button>
          ))}
        </div>
        {c.notFinished > 0 ? <span className="text-sm text-muted">{`${c.notFinished} not finished`}</span> : null}
      </div>
      <div className="overflow-hidden rounded-xl border border-line">
        <table aria-label="Packages" className="w-full table-fixed border-collapse text-left">
          <colgroup>
            <col className="w-[30%]" />
            <col className="w-[148px]" />
            <col />
          </colgroup>
          <thead className="bg-card text-xs font-semibold text-muted">
            <tr>
              <th scope="col" className="px-3.5 py-2 font-semibold">
                Package
              </th>
              <th scope="col" className="px-3.5 py-2 font-semibold">
                State
              </th>
              <th scope="col" className="px-3.5 py-2 font-semibold">
                Detail
              </th>
            </tr>
          </thead>
          <tbody>
            {visible.map((p, i) => (
              <PackageRow key={`${i}-${p.name}@${p.version}`} p={p} />
            ))}
          </tbody>
        </table>
      </div>
      {visible.length < shown.length ? (
        <button
          type="button"
          onClick={() => setAll(true)}
          className="mt-3 inline-flex h-8 items-center rounded-md border border-line bg-card px-3 text-sm outline-none hover:bg-background focus-visible:ring-2 focus-visible:ring-accent"
        >
          {`Show ${shown.length - visible.length} more`}
        </button>
      ) : null}
    </div>
  )
}
