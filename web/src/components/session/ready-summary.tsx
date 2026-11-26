import { ArrowDown, ArrowRight, ArrowUp, Shield } from "lucide-react"

import { SeverityMark } from "@/components/session/review-panels"
import { Term } from "@/components/ui/term"
import { cn } from "@/lib/utils"

interface ReadySummaryProps {
  /** Known CVEs by severity before the update, critical to unknown. */
  before: number[]
  /** Known CVEs by severity the selection keeps, critical to unknown. */
  after: number[]
  /** False when the after figure sums each package's own scan instead of the combined check's. */
  checkedTogether: boolean
  directDependencies: number
}

const SEVERITIES = ["critical", "high", "medium", "low", "unknown"] as const

const count = (n: number) => n.toLocaleString("en-US")
const total = (vector: number[]) => vector.reduce((sum, n) => sum + n, 0)

/** Ready's head: the known CVEs before and after, then each severity's, each with what the selection changes. */
export function ReadySummary({ before, after, checkedTogether, directDependencies }: ReadySummaryProps) {
  // Unknown joins the four only when a count holds one, so the columns always add up to the total.
  const shown = SEVERITIES.map((severity, index) => ({ severity, before: before[index] ?? 0, after: after[index] ?? 0 })).filter(
    (entry) => entry.severity !== "unknown" || entry.before > 0 || entry.after > 0,
  )

  return (
    <>
      <p className="mb-5 text-[15px] text-muted">
        <span className="figure text-ink">{count(directDependencies)}</span> {directDependencies === 1 ? "direct dependency" : "direct dependencies"}
      </p>
      <section aria-label="Known CVEs" className="mb-3 grid rounded-xl border border-rule-2 bg-bg sm:grid-cols-[13.5rem_minmax(0,1fr)]">
        <div data-total-block className="flex min-w-0 flex-col px-5 py-4">
          <p className="flex items-center gap-1.5 text-[13px] font-semibold text-muted">
            <Shield aria-hidden="true" className="size-3.5" />
            Known CVEs
            <Term id="cve" />
          </p>
          <p data-total className="mt-1 flex items-center gap-2.5 text-[34px] leading-tight tracking-tight tabular-nums">
            <span className="text-muted">{count(total(before))}</span>
            <ArrowRight aria-hidden="true" className="size-5 flex-none text-faint" />
            <span className="sr-only"> to </span>
            <span className="font-semibold text-ink">{count(total(after))}</span>
          </p>
          {checkedTogether ? null : <p className="text-[13px] text-muted">Not checked together</p>}
          <Delta before={total(before)} after={total(after)} className="mt-2.5" />
        </div>
        <div className="min-w-0 border-t border-rule px-5 py-4 sm:border-t-0 sm:border-l">
          <p className="flex items-center gap-1 text-[13px] font-semibold text-muted">
            By severity
            <Term id="severity" />
          </p>
          <ul className="mt-1.5 grid grid-cols-[repeat(auto-fit,minmax(6.5rem,1fr))] gap-y-3">
            {shown.map((entry) => (
              <li key={entry.severity} data-severity className="flex min-w-0 flex-col gap-1.5 border-rule pr-3 [&:not(:first-child)]:border-l [&:not(:first-child)]:pl-3.5">
                <SeverityMark severity={entry.severity} />
                <span className="inline-flex items-center gap-1.5 text-[15px] whitespace-nowrap text-muted tabular-nums">
                  {count(entry.before)}
                  <ArrowRight aria-hidden="true" className="size-3 flex-none text-faint" />
                  <span className="sr-only"> to </span>
                  <span className="font-semibold text-ink">{count(entry.after)}</span>
                </span>
                <Delta before={entry.before} after={entry.after} />
              </li>
            ))}
          </ul>
        </div>
      </section>
    </>
  )
}

/** What the selection changes in a count: down green, up red, each with its arrow and sign; 0 faint. */
function Delta({ before, after, className }: { before: number; after: number; className?: string }) {
  const change = after - before
  if (change === 0) {
    return (
      <span data-delta className={cn("inline-flex h-5.5 items-center self-start font-mono text-[12.5px] font-medium text-faint", className)}>
        0
      </span>
    )
  }
  const down = change < 0
  const Arrow = down ? ArrowDown : ArrowUp
  return (
    <span
      data-delta
      className={cn(
        "inline-flex h-5.5 items-center gap-0.5 self-start rounded-full border px-1.5 font-mono text-[12.5px] font-semibold whitespace-nowrap",
        down ? "border-ok-line bg-ok-tint text-ok" : "border-bad-line bg-bad-tint text-bad",
        className,
      )}
    >
      <Arrow aria-hidden="true" className="size-3 stroke-[2.25]" />
      {down ? `−${count(-change)}` : `+${count(change)}`}
    </span>
  )
}
