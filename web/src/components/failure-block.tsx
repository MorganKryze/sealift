import { useQuery } from "@tanstack/react-query"
import type { ReactNode, SyntheticEvent } from "react"

import { getAnalysisLog } from "@/api/projects"

interface FailureBlockProps {
  projectId: string
  analysisId: string
  /** Short cause, e.g. "sealift could not download the vulnerability database." */
  message: string
  /** What stays true despite the failure, e.g. "Your file is kept; retrying starts again from the scan." */
  detail?: string
  heading?: string
  /** "neutral" for a stop the user asked for, such as a cancel. */
  tone?: "failure" | "neutral"
  /** Next-action buttons: retry, open settings, choose another file. */
  actions: ReactNode
}

/**
 * Shown when a job stops: the cause, what to do next, and the full log
 * folded behind a summary, fetched only once opened. A failure reason kept
 * only in log.txt is a defect, so the message above always comes from the
 * job's own failure record, never "see the log".
 */
export function FailureBlock({ projectId, analysisId, message, detail, heading = "Analysis stopped", tone = "failure", actions }: FailureBlockProps) {
  const logQuery = useQuery({
    queryKey: ["analysis-log", projectId, analysisId],
    queryFn: () => getAnalysisLog(projectId, analysisId),
    enabled: false,
  })

  function handleToggle(event: SyntheticEvent<HTMLDetailsElement>) {
    if (event.currentTarget.open && !logQuery.isFetched) {
      void logQuery.refetch()
    }
  }

  return (
    <div
      role={tone === "failure" ? "alert" : "status"}
      className={
        "animate-enter mt-4 rounded-xl border p-5 " +
        (tone === "failure" ? "border-severity-critical/35 bg-severity-critical/5" : "border-line bg-card")
      }
    >
      <h3 className={"text-base font-semibold " + (tone === "failure" ? "text-severity-critical-fg" : "text-ink")}>{heading}</h3>
      <p className="mt-1.5 max-w-[70ch] text-sm text-ink">{message}</p>
      {detail ? <p className="mt-1.5 max-w-[70ch] text-xs text-muted">{detail}</p> : null}
      <div className="mt-3.5 flex flex-wrap gap-3">{actions}</div>
      <details className="mt-3.5" onToggle={handleToggle}>
        <summary className="cursor-pointer text-sm text-muted">Show the log</summary>
        <pre className="mt-2.5 max-h-72 overflow-auto rounded-lg border border-line bg-background p-3.5 font-mono text-xs leading-relaxed whitespace-pre-wrap text-ink">
          {logQuery.isPending || logQuery.isFetching
            ? "Loading…"
            : logQuery.isError
              ? "Could not load the log."
              : (logQuery.data ?? "")}
        </pre>
      </details>
    </div>
  )
}
