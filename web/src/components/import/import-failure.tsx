import { Button } from "@/components/ui/button"

interface ImportFailureProps {
  title: string
  cause: string
  next: string
  /** The technical detail, folded. */
  detail?: string
  onRetry: () => void
  actionLabel?: string
}

/** A failure in three parts: the cause, the next action and, folded, the technical detail. */
export function ImportFailure({ title, cause, next, detail, onRetry, actionLabel = "Try again" }: ImportFailureProps) {
  return (
    <div role="alert" className="rounded-xl border border-severity-critical bg-card p-6">
      <h2 className="text-lg font-semibold tracking-tight text-ink">{title}</h2>
      <p className="mt-2 max-w-[62ch] text-ink [overflow-wrap:anywhere]">{cause}</p>
      <p className="mt-2 max-w-[62ch] text-muted">{next}</p>
      <div className="mt-4">
        <Button onClick={onRetry}>{actionLabel}</Button>
      </div>
      {detail ? (
        <details className="mt-4">
          <summary className="inline-flex h-8 cursor-pointer items-center text-sm text-muted outline-none hover:text-ink focus-visible:ring-2 focus-visible:ring-accent">Technical detail</summary>
          <pre className="mt-2 max-h-48 overflow-auto rounded-md border border-line bg-background p-3 font-mono text-xs whitespace-pre-wrap [overflow-wrap:anywhere]">{detail}</pre>
        </details>
      ) : null}
    </div>
  )
}
