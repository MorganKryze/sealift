import { useQueryClient } from "@tanstack/react-query"
import { createFileRoute, Link } from "@tanstack/react-router"
import { CircleX } from "lucide-react"

import { ApiFailure } from "@/components/import/api-failure"
import { EarlierAttempts } from "@/components/import/earlier-attempts"
import { EndState } from "@/components/import/end-state"
import { ImportPageHeader } from "@/components/import/import-header"
import { AttemptProgress, attemptSteps } from "@/components/import/progress"
import { RefusedDetails } from "@/components/import/refused-panel"
import { RetryCard } from "@/components/import/retry-card"
import { ShaBlock } from "@/components/import/sha-block"
import { StepBar } from "@/components/step-bar"
import { ImportApiError, SessionEnded } from "@/import/api/client"
import { useImport, useMe, type ArchiveList } from "@/import/api/queries"
import { latestAttempt } from "@/import/lib/outcome"

export const Route = createFileRoute("/imports/$importId")({
  component: ImportRoute,
})

const back =
  "mb-5 inline-flex h-8 items-center self-start rounded-md text-sm text-accent underline outline-none focus-visible:ring-2 focus-visible:ring-accent"

function ImportRoute() {
  const { importId } = Route.useParams()
  const query = useImport(importId)
  const me = useMe()
  const client = useQueryClient()
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
  // While it waits, runs, or once cancelled, the progress is the page; any other end keeps today's account until it is redrawn.
  const live = attempt.status !== "ended" || attempt.outcome === "cancelled"
  const refused = attempt.status === "ended" && attempt.outcome === "refused"
  // The home's list, when this tab read it, gives each file's upload time; the page never lists the folder itself.
  const listed = client.getQueryData<ArchiveList>(["archives"])?.archives.find((a) => a.key === imp.archive.key)
  return (
    <>
      <Link to="/imports" className={back}>
        All imports
      </Link>
      <div className="mx-auto w-full max-w-190">
        <StepBar steps={attemptSteps(attempt)} label="Import steps" />
        {query.isError ? <p className="mb-4 text-sm text-severity-critical-fg">The last refresh failed. The page is as it was.</p> : null}
        {live ? <AttemptProgress key={attempt.n} imp={imp} attempt={attempt} /> : null}
      </div>
      {live ? null : (
        <>
          <ImportPageHeader imp={imp} />
          {refused ? (
            <section aria-labelledby="refused-heading" className="mt-6 max-w-190 rounded-xl border border-bad-line p-5">
              <h2 id="refused-heading" className="mb-4 inline-flex items-center gap-2 text-lg font-semibold text-bad">
                <CircleX aria-hidden="true" className="size-5" />
                Refused
              </h2>
              <RefusedDetails imp={imp} archive={listed} trusted={me.data?.publicKeySha256 ?? attempt.report.publicKeySha256 ?? ""} />
            </section>
          ) : (
            <>
              <EndState imp={imp} />
              {attempt.outcome === "incomplete" || attempt.outcome === "interrupted" ? <RetryCard imp={imp} /> : null}
              <h2 className="mt-8 mb-3 text-lg font-semibold tracking-tight">Archive sha256 check</h2>
              <ShaBlock expected={imp.expectedSha256} manifest={attempt.report.archive.sha256} checked={attempt.report.archiveChecked} publicKey={attempt.report.publicKeySha256} status={attempt.status} />
            </>
          )}
        </>
      )}
      <div className="mt-8">
        <EarlierAttempts attempts={imp.attempts.filter((a) => a.n !== attempt.n)} />
      </div>
    </>
  )
}
