import { createFileRoute, Link } from "@tanstack/react-router"

import { ApiFailure } from "@/components/import/api-failure"
import { EarlierAttempts } from "@/components/import/earlier-attempts"
import { EndState } from "@/components/import/end-state"
import { ImportPageHeader } from "@/components/import/import-header"
import { AttemptProgress } from "@/components/import/progress"
import { ReportList } from "@/components/import/report-list"
import { RetryCard } from "@/components/import/retry-card"
import { ShaBlock } from "@/components/import/sha-block"
import { ImportApiError, SessionEnded } from "@/import/api/client"
import { useImport } from "@/import/api/queries"
import { latestAttempt } from "@/import/lib/outcome"

export const Route = createFileRoute("/imports/$importId")({
  component: ImportRoute,
})

const back =
  "mb-5 inline-flex h-8 items-center self-start rounded-md text-sm text-accent underline outline-none focus-visible:ring-2 focus-visible:ring-accent"

function ImportRoute() {
  const { importId } = Route.useParams()
  const query = useImport(importId)
  const imp = query.data

  if (query.isPending) {
    return (
      <div role="status" className="text-muted">
        Loading the import
      </div>
    )
  }
  if (!imp || query.error instanceof SessionEnded) {
    if (query.error instanceof ImportApiError && query.error.status === 404) {
      return (
        <>
          <h1 className="text-2xl font-bold tracking-tight">No such import</h1>
          <p className="mt-2 max-w-[62ch] text-muted">None of your imports has this id. It may belong to another user, or it was never started.</p>
          <Link to="/imports" className={`${back} mt-4`}>
            Go to imports
          </Link>
        </>
      )
    }
    return <ApiFailure error={query.error} onRetry={() => void query.refetch()} />
  }

  const attempt = latestAttempt(imp)
  return (
    <>
      <Link to="/imports" className={back}>
        All imports
      </Link>
      <ImportPageHeader imp={imp} />
      {query.isError ? <p className="mt-4 text-sm text-severity-critical-fg">The last refresh failed. The page is as it was.</p> : null}
      <div className="mt-6">
        <AttemptProgress attempt={attempt} />
      </div>
      <EndState imp={imp} />
      {attempt.status === "ended" && (attempt.outcome === "incomplete" || attempt.outcome === "interrupted") ? <RetryCard imp={imp} /> : null}
      <h2 className="mt-8 mb-3 text-lg font-semibold tracking-tight">Archive sha256 check</h2>
      <ShaBlock expected={imp.expectedSha256} manifest={attempt.report.archive.sha256} checked={attempt.report.archiveChecked} />
      <h2 className="mt-8 mb-3 text-lg font-semibold tracking-tight">Packages</h2>
      <ReportList key={attempt.n} attempt={attempt} />
      <div className="mt-8">
        <EarlierAttempts attempts={imp.attempts.filter((a) => a.n !== attempt.n)} />
      </div>
    </>
  )
}
