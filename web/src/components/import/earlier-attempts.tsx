import { ChevronDown, ChevronRight } from "lucide-react"
import { useState } from "react"

import { counts, type Attempt } from "@/import/lib/outcome"
import { formatWhen } from "@/lib/utils"

import { OutcomeBadge } from "./outcome-badge"
import { ReportList } from "./report-list"

const toggle =
  "inline-flex h-8 items-center gap-1.5 rounded-md text-sm outline-none hover:text-ink focus-visible:ring-2 focus-visible:ring-accent"

function EarlierAttempt({ attempt }: { attempt: Attempt }) {
  const [open, setOpen] = useState(false)
  const c = counts(attempt)
  return (
    <li className="border-t border-line px-5 py-3 first:border-t-0">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 text-sm">
        <span className="font-medium">{`Attempt ${attempt.n}`}</span>
        <OutcomeBadge outcome={attempt.status === "ended" ? attempt.outcome : attempt.status} />
        <span>
          <b className="font-mono font-semibold">{c.published}</b> published, <b className="font-mono font-semibold">{c.present}</b> present,{" "}
          <b className="font-mono font-semibold">{c.failed + c.notFinished}</b> failed
        </span>
        <span className="text-muted">{attempt.endedAt ? `Ended ${formatWhen(attempt.endedAt)}` : "Ended: Not recorded"}</span>
        <button type="button" aria-expanded={open} onClick={() => setOpen(!open)} className={`${toggle} ml-auto text-accent underline`}>
          {open ? `Hide report of attempt ${attempt.n}` : `Show report of attempt ${attempt.n}`}
        </button>
      </div>
      {open ? (
        <div role="region" aria-label={`Report of attempt ${attempt.n}`} className="mt-3">
          <ReportList attempt={attempt} />
        </div>
      ) : null}
    </li>
  )
}

/** The attempts before the latest, folded, each with its report on demand. */
export function EarlierAttempts({ attempts }: { attempts: Attempt[] }) {
  const [open, setOpen] = useState(false)
  if (attempts.length === 0) {
    return null
  }
  const Chevron = open ? ChevronDown : ChevronRight
  return (
    <section>
      <button type="button" aria-expanded={open} onClick={() => setOpen(!open)} className={`${toggle} text-ink font-medium`}>
        <Chevron aria-hidden className="size-4" />
        {`Earlier attempts (${attempts.length})`}
      </button>
      {open ? (
        <ul aria-label="Earlier attempts" className="mt-2 overflow-hidden rounded-xl border border-line">
          {attempts.map((a) => (
            <EarlierAttempt key={a.n} attempt={a} />
          ))}
        </ul>
      ) : null}
    </section>
  )
}
