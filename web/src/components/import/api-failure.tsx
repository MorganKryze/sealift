import { Button } from "@/components/ui/button"
import { ImportApiError, SessionEnded } from "@/import/api/client"

interface ApiFailureProps {
  error: unknown
  onRetry?: () => void
  /** What the failure left as it was, said after the next action. */
  untouched?: string
}

/** Names the cause of a failed request and the next action, in words. */
export function ApiFailure({ error, onRetry, untouched }: ApiFailureProps) {
  if (error instanceof SessionEnded) {
    return (
      <Frame title="Your session has ended">
        <p className="mt-2 max-w-[62ch] text-ink">The page was signed out while you were away. Sign in again to carry on; nothing you started was changed.</p>
        <div className="mt-4">
          <Button onClick={() => location.reload()}>Sign in again</Button>
        </div>
      </Frame>
    )
  }
  if (error instanceof ImportApiError) {
    const cause = error.problem?.detail ?? error.problem?.title ?? "The request failed."
    const next =
      error.status === 403
        ? "Ask the administrator: this user name cannot be given a folder."
        : error.status === 503
          ? "Try again later: the service cannot check your sign-in right now, or it is stopping."
          : null
    return (
      <Frame title="This could not be loaded">
        <p className="mt-2 max-w-[62ch] break-words text-ink">{cause}</p>
        {next ? <p className="mt-2 max-w-[62ch] text-muted">{next}</p> : null}
        {untouched ? <p className="mt-2 max-w-[62ch] text-muted">{untouched}</p> : null}
        {error.status !== 403 && onRetry ? (
          <div className="mt-4">
            <Button onClick={onRetry}>Try again</Button>
          </div>
        ) : null}
      </Frame>
    )
  }
  return (
    <Frame title="Something went wrong">
      <p className="mt-2 max-w-[62ch] break-words text-ink">{error instanceof Error ? error.message : "The screen could not read the answer."}</p>
      {untouched ? <p className="mt-2 max-w-[62ch] text-muted">{untouched}</p> : null}
      {onRetry ? (
        <div className="mt-4">
          <Button onClick={onRetry}>Try again</Button>
        </div>
      ) : null}
    </Frame>
  )
}

function Frame({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div role="alert" className="rounded-xl border border-severity-critical bg-card p-6">
      <h2 className="text-lg font-semibold tracking-tight text-ink">{title}</h2>
      {children}
    </div>
  )
}
