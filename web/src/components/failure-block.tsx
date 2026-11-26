import { useQuery } from "@tanstack/react-query"
import { CircleX, Info } from "lucide-react"
import type { ReactNode } from "react"

import { getAnalysisLog } from "@/api/projects"
import { ContactCard } from "@/components/frame/brand"
import { LogBlock } from "@/components/job-progress"
import { lineTone, type LogLine } from "@/lib/analysisEvents"
import { cn } from "@/lib/utils"

/** A stop's cause in words: what was seen, the packages it names, and what it rules out. */
export interface FailureCause {
  title: string
  /** What the items count, "1 package". */
  count?: string
  items?: { name: string; value: string }[]
  diagnosis: string
}

interface FailureBlockProps {
  projectId: string
  analysisId: string
  heading: string
  /** How long it ran and what is kept. */
  sub: ReactNode
  cause?: FailureCause
  /** "neutral" for a stop the developer asked for or a restart: no red and no contact. */
  tone: "failure" | "neutral"
  /** The one action that clears the cause, at the cause's right; with no cause, the page's action row. */
  actions: ReactNode
}

// The log file holds what the job wrote, line by line, with no receipt time.
function fileLines(text: string): LogLine[] {
  const lines = text.split("\n")
  if (lines.at(-1) === "") lines.pop()
  return lines.map((line) => {
    const tone = lineTone(line)
    return { at: "", step: "", text: line, ...(tone ? { tone } : {}) }
  })
}

/**
 * A stopped job: its title, then one closed block with the cause in words and the action that clears
 * it, the log folded behind its count, and the deployment's contact last. A cause kept only in the log
 * is a defect, so the block always reads from the job's own failure record; the raw text a tool wrote
 * stays in the log.
 */
export function FailureBlock({ projectId, analysisId, heading, sub, cause, tone, actions }: FailureBlockProps) {
  const logQuery = useQuery({
    queryKey: ["analysis-log", projectId, analysisId],
    queryFn: () => getAnalysisLog(projectId, analysisId),
  })
  const failure = tone === "failure"

  return (
    <div>
      <h1 className="text-[28px] font-bold tracking-tight text-ink">{heading}</h1>
      <p className="mt-1 text-[15px] text-muted">{sub}</p>
      {cause ? (
        <div
          role={failure ? "alert" : undefined}
          className={cn(
            "animate-enter mt-5 grid grid-cols-[20px_minmax(0,1fr)] items-start gap-x-3 gap-y-3 px-4 py-3.5 sm:grid-cols-[20px_minmax(0,1fr)_auto]",
            failure ? "tinted-bad" : "rounded-lg border border-rule-2",
          )}
        >
          {failure ? <CircleX aria-hidden="true" className="mt-0.5 size-5 text-bad" /> : <Info aria-hidden="true" className="mt-0.5 size-5 text-muted" />}
          <div className="min-w-0">
            <p className="flex flex-wrap items-center gap-x-2 gap-y-1">
              <span className="font-semibold text-ink [overflow-wrap:anywhere]">{cause.title}</span>
              {cause.count ? <span className="rounded-full border border-bad-line bg-bg px-2 text-xs leading-5 font-semibold text-bad">{cause.count}</span> : null}
            </p>
            {cause.items?.length ? (
              <ul className="mt-2 flex flex-wrap gap-2">
                {cause.items.map((item) => (
                  <li key={`${item.name}@${item.value}`} className="rounded-md border border-bad-line bg-bg px-2 py-0.5 font-mono text-[12.5px] text-ink [overflow-wrap:anywhere]">
                    <span>{item.name}</span> <span className="font-semibold">{item.value}</span>
                  </li>
                ))}
              </ul>
            ) : null}
            <p className="mt-1.5 max-w-[62ch] text-[13px] text-ink-2">{cause.diagnosis}</p>
          </div>
          <div className="col-start-2 flex flex-wrap gap-3 self-end sm:col-start-3">{actions}</div>
        </div>
      ) : null}
      <LogBlock
        className="mt-3"
        lines={logQuery.data === undefined ? [] : fileLines(logQuery.data)}
        status={logQuery.isError ? "The log did not load." : logQuery.data === undefined ? "Loading" : undefined}
        copyText={logQuery.data || undefined}
      />
      {cause ? null : <div className="mt-7 flex flex-wrap items-center justify-end gap-3">{actions}</div>}
      {failure ? <ContactCard /> : null}
    </div>
  )
}
