import { Progress } from "@/components/ui/progress"
import { counts, outcomeWords, type Attempt } from "@/import/lib/outcome"
import { stageOf } from "@/import/lib/stage"

function Counts({ attempt, pending }: { attempt: Attempt; pending: boolean }) {
  const c = counts(attempt)
  return (
    <p className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-sm">
      <span>
        <b className="font-mono font-semibold">{c.published}</b> published
      </span>
      <span>
        <b className="font-mono font-semibold">{c.present}</b> present
      </span>
      <span>
        <b className="font-mono font-semibold">{c.failed}</b> failed
      </span>
      {c.notFinished > 0 ? (
        <span>
          <b className="font-mono font-semibold">{c.notFinished}</b> not finished
        </span>
      ) : null}
      {pending ? (
        <span>
          <b className="font-mono font-semibold">{c.pending}</b> pending
        </span>
      ) : null}
    </p>
  )
}

function Region({ attempt }: { attempt: Attempt }) {
  const stage = stageOf(attempt)
  const c = counts(attempt)
  return (
    <div role="status" tabIndex={-1} className="rounded-xl border border-line bg-card p-5 outline-none focus-visible:ring-2 focus-visible:ring-accent">
      {stage === "waiting" ? (
        <>
          <p className="font-medium">Waiting its turn</p>
          <p className="mt-1 text-sm text-muted">One import runs at a time for every user of the service, in the order they were started.</p>
        </>
      ) : null}
      {stage === "manifest" ? <p className="font-medium">Reading the manifest</p> : null}
      {stage === "checks" ? (
        <>
          <p className="font-medium">Checking the archive</p>
          <p className="mt-1 text-sm text-muted">The check reads the whole archive once and shows no byte progress. A large archive can take minutes.</p>
        </>
      ) : null}
      {stage === "publishing" ? (
        <>
          <p className="font-medium">{`Publishing packages: ${c.done} of ${c.total}`}</p>
          <Progress className="mt-3" value={c.total > 0 ? (c.done / c.total) * 100 : 0} label="Packages done" />
          <Counts attempt={attempt} pending />
        </>
      ) : null}
      {stage === "ended" ? (
        <>
          <p className="font-medium">{`Attempt ${attempt.n} ended: ${outcomeWords(attempt.outcome).label}`}</p>
          <Counts attempt={attempt} pending={false} />
        </>
      ) : null}
    </div>
  )
}

/**
 * The one status region of the import page. The region is keyed by attempt number: a refetch of the
 * same attempt updates it in place, and a new attempt mounts a fresh one.
 */
export function AttemptProgress({ attempt }: { attempt: Attempt }) {
  return <Region key={attempt.n} attempt={attempt} />
}
