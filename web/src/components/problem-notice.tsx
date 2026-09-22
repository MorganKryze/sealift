import { Link } from "@tanstack/react-router"
import type { ReactNode } from "react"

import type { Problem } from "@/api/projects"
import { cn } from "@/lib/utils"

interface ProblemNoticeProps {
  status: number
  problem: Problem | null
  className?: string
  children?: ReactNode
}

/**
 * Renders a Problem Details failure: every offending entry for a 400 with
 * a field-level errors list, otherwise the title and detail. The children
 * (for example a link to Settings) only show next to the title/detail form,
 * since a field-level list already explains itself.
 */
export function ProblemNotice({ status, problem, className, children }: ProblemNoticeProps) {
  const details = problem?.errors

  return (
    <div
      role="alert"
      className={cn(
        "w-full rounded-lg border border-severity-critical/40 bg-severity-critical/5 p-4 text-left text-sm text-ink",
        className,
      )}
    >
      {status === 400 && details && details.length > 0 ? (
        <ul className="space-y-1.5">
          {details.map((entry, index) => (
            <li key={index}>
              <span className="font-mono text-xs text-muted">{entry.field}</span>
              {entry.name ? <span className="font-mono text-xs text-muted"> · {entry.name}</span> : null}
              {entry.value ? <span className="font-mono text-xs text-muted"> · {entry.value}</span> : null}
              <span>: {entry.reason}</span>
            </li>
          ))}
        </ul>
      ) : (
        <>
          <p className="font-medium">{problem?.title ?? "Request failed"}</p>
          {problem?.detail ? <p className="text-muted">{problem.detail}</p> : null}
          {problem?.type === "tools-missing" ? (
            <Link to="/" className="mt-2 inline-block font-medium text-accent underline underline-offset-2">
              Open setup
            </Link>
          ) : null}
          {children}
        </>
      )}
    </div>
  )
}
