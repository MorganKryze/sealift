import { RotateCw } from "lucide-react"

import { Button } from "@/components/ui/button"
import { ImportApiError } from "@/import/api/client"
import { retryGroups, useRetryImport, type Import } from "@/import/api/queries"
import { nextAction } from "@/import/lib/kinds"
import { latestAttempt } from "@/import/lib/outcome"

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`

/**
 * The retry button and what its refusal says. A 409 names its cause in the service's words; the next
 * action is one sentence that fits every cause.
 */
export function RetryAction({ imp }: { imp: Import }) {
  const retry = useRetryImport(imp.id)
  const refused = retry.error instanceof ImportApiError && retry.error.status === 409
  const failure = retry.isError ? retry.error : null
  return (
    <div className="mt-4">
      <Button onClick={() => retry.mutate()} disabled={retry.isPending}>
        <RotateCw aria-hidden />
        {retry.isPending ? "Starting the retry" : "Retry import"}
      </Button>
      {failure ? (
        <div role="alert" className="mt-4 rounded-lg border border-severity-critical bg-background p-4 text-sm">
          <p className="font-medium">{refused ? "The retry was refused" : "The retry could not be started"}</p>
          <p className="mt-1 max-w-[62ch] [overflow-wrap:anywhere]">{failure instanceof ImportApiError ? (failure.problem?.detail ?? failure.problem?.title ?? failure.message) : failure.message}</p>
          <p className="mt-1 max-w-[62ch] text-muted">
            {refused
              ? "Nothing was changed, and this page now shows the import as it stands. If the archive is gone from MinIO, upload it again and start a new import from Archives."
              : "Nothing was changed. Try again; if it fails again, check that the service answers."}
          </p>
        </div>
      ) : null}
    </div>
  )
}

/** Above the report of an incomplete or an interrupted attempt: what is missing, what a retry does, and what it cannot clear alone. */
export function RetryCard({ imp }: { imp: Import }) {
  const attempt = latestAttempt(imp)
  const g = retryGroups(attempt.report.packages)
  const total = attempt.report.packages.length
  return (
    <section aria-labelledby="retry-heading" className="mt-6 rounded-xl border border-line bg-card p-5">
      <h2 id="retry-heading" className="text-lg font-semibold tracking-tight">
        {`${g.notInNexus} of ${total} ${total === 1 ? "package is" : "packages are"} not in Nexus`}
      </h2>
      <p className="mt-2 max-w-[62ch]">{`Retry adds attempt ${attempt.n + 1} to this import. It starts from the beginning and trusts nothing from the earlier attempt:`}</p>
      <ul className="mt-2 grid max-w-[62ch] list-disc gap-1 pl-5">
        <li>Reads the archive and its manifest from MinIO again and checks the sha256 again.</li>
        <li>{`Reads all ${total} ${total === 1 ? "package" : "packages"} from Nexus again. ${total - g.notInNexus} ${total - g.notInNexus === 1 ? "is" : "are"} there already and stay untouched; it uploads only what Nexus does not have.`}</li>
        <li>Removes the archive from MinIO only once every package is in Nexus.</li>
      </ul>
      <div className="mt-4 grid max-w-[72ch] gap-3 text-sm">
        {g.asIs > 0 ? (
          <div role="group" aria-label="Can succeed on retry">
            <p className="font-medium">Can succeed on retry</p>
            <p className="mt-1 text-muted">{`${plural(g.asIs, "package", "packages")}: a retry checks them in Nexus and uploads the ones it lacks. Nothing outside sealift needs to change first.`}</p>
          </div>
        ) : null}
        {g.changeFirst.length > 0 ? (
          <div role="group" aria-label="Fails again until fixed outside sealift">
            <p className="font-medium">Fails again until fixed outside sealift</p>
            <ul className="mt-1 grid gap-1.5 text-muted">
              {g.changeFirst.map((c) => (
                <li key={c.kind}>
                  <b className="font-mono font-semibold text-ink">{`${c.count} ${c.kind}`}</b>
                  {`: ${c.words}`}
                </li>
              ))}
            </ul>
          </div>
        ) : null}
        {g.unknown > 0 ? (
          <div role="group" aria-label="Cause not recorded">
            <p className="font-medium">Cause not recorded</p>
            <p className="mt-1 text-muted">{`${plural(g.unknown, "package", "packages")}: ${nextAction().words}`}</p>
          </div>
        ) : null}
      </div>
      <RetryAction imp={imp} />
    </section>
  )
}
