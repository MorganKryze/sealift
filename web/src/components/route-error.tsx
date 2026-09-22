import { Link, useRouter, type ErrorComponentProps } from "@tanstack/react-router"

import { Button } from "@/components/ui/button"

function ErrorLayout({ title, detail, children }: { title: string; detail: string; children: React.ReactNode }) {
  return (
    <div className="animate-enter mx-auto flex w-full max-w-240 flex-1 flex-col px-5 py-8">
      <div role="alert" className="rounded-xl border border-severity-critical/40 bg-severity-critical/5 p-6">
        <h1 className="text-xl font-bold tracking-tight text-ink">{title}</h1>
        <p className="mt-2 max-w-[62ch] text-muted">{detail}</p>
        <div className="mt-5 flex flex-wrap gap-2">{children}</div>
      </div>
    </div>
  )
}

/** Replaces the router's default "Something went wrong!" for any screen that throws. */
export function RouteError({ error, reset }: ErrorComponentProps) {
  const router = useRouter()

  return (
    <ErrorLayout
      title="This screen could not load"
      detail="sealift hit an error while showing this page. Your sessions and archives are safe on the server; try again, or go back to your sessions."
    >
      <Button
        onClick={() => {
          reset()
          void router.invalidate()
        }}
      >
        Try again
      </Button>
      <Button variant="outline" asChild>
        <Link to="/">Back to sessions</Link>
      </Button>
      <details className="mt-3 w-full text-sm text-muted">
        <summary className="cursor-pointer">Technical detail</summary>
        <pre className="mt-2 overflow-x-auto rounded-md border border-line bg-background p-3 font-mono text-xs text-ink">
          {error instanceof Error ? error.message : String(error)}
        </pre>
      </details>
    </ErrorLayout>
  )
}

export function RouteNotFound() {
  return (
    <ErrorLayout title="Nothing here" detail="This address matches no screen and no session. The session may have been deleted.">
      <Button asChild>
        <Link to="/">Back to sessions</Link>
      </Button>
    </ErrorLayout>
  )
}

/** A session that failed to load: gone (404), or unreachable for another reason with its cause. */
export function SessionLoadError({ error, onRetry }: { error: unknown; onRetry: () => void }) {
  const status = typeof error === "object" && error && "status" in error ? (error as { status: number }).status : undefined
  if (status === 404) {
    return (
      <ErrorLayout title="This session no longer exists" detail="It may have been deleted. Start a new session from the home screen.">
        <Button asChild>
          <Link to="/">Back to sessions</Link>
        </Button>
      </ErrorLayout>
    )
  }
  return (
    <ErrorLayout
      title="Could not load this session"
      detail={`The server did not answer as expected${error instanceof Error ? `: ${error.message.replace(/\.$/, "")}.` : "."} Check that sealift is still running, then try again.`}
    >
      <Button onClick={onRetry}>Try again</Button>
      <Button variant="outline" asChild>
        <Link to="/">Back to sessions</Link>
      </Button>
    </ErrorLayout>
  )
}
