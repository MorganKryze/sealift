import { Link } from "@tanstack/react-router"
import { Archive, CircleCheck, CirclePause, Info, ShieldX, type LucideIcon } from "lucide-react"
import type { ReactNode } from "react"

import { counts, latestAttempt, type Import } from "@/import/lib/outcome"
import { formatWhen } from "@/lib/utils"

import { CopyControl } from "./copy-control"
import { RetryAction } from "./retry-card"

function Card({ icon: Icon, tone, title, children, panel = "border-line bg-card" }: { icon: LucideIcon; tone: string; title: ReactNode; children: ReactNode; panel?: string }) {
  return (
    <section aria-labelledby="end-heading" className={`mt-6 rounded-xl border p-5 ${panel}`}>
      <div className="flex items-start gap-2">
        <Icon aria-hidden className={`mt-1 size-[18px] shrink-0 ${tone}`} />
        <h2 id="end-heading" className="text-lg font-semibold tracking-tight">
          {title}
        </h2>
      </div>
      <div className="mt-2 grid max-w-[72ch] gap-2">{children}</div>
    </section>
  )
}

function Etag({ title, value, label }: { title: string; value: string; label: string }) {
  return (
    <div>
      <dt className="text-sm text-muted">{title}</dt>
      <dd className="mt-1 flex flex-wrap items-start gap-x-3 gap-y-2">
        <code className="min-w-0 font-mono text-[13px] [overflow-wrap:anywhere]">{value}</code>
        <CopyControl text={value} label={label} />
      </dd>
    </div>
  )
}

/** The words for the counts of a complete attempt. Only a complete attempt says every package is in Nexus. */
function inNexus(imp: Import): string {
  const c = counts(latestAttempt(imp))
  return `All ${c.total} packages are in Nexus: ${c.published} published, ${c.present} present.`
}

/**
 * How the latest attempt ended, in the cases the report and the progress cannot say: a complete
 * attempt and what became of the archive, a refusal, an interruption. An incomplete attempt is the
 * retry card's. The archive's removal is read from the attempt's removal record alone.
 */
export function EndState({ imp }: { imp: Import }) {
  const a = latestAttempt(imp)
  if (a.status !== "ended") {
    return null
  }
  if (a.outcome === "complete") {
    if (!a.removal) {
      return (
        <Card icon={Info} tone="text-accent" title="Checking the archive's removal">
          <p>{inNexus(imp)}</p>
          <p className="text-muted">The archive's removal is being checked. This page updates until the service records what became of it.</p>
        </Card>
      )
    }
    if (a.removal.removed) {
      return (
        <Card icon={CircleCheck} tone="text-severity-resolved-fg" title={a.removal.reason ? "Archive removed from MinIO, manifest kept" : "Archive removed from MinIO"}>
          <p>{inNexus(imp)}</p>
          {a.removal.reason ? (
            <p className="[overflow-wrap:anywhere]">{a.removal.reason}</p>
          ) : (
            <p>sealift removed both objects from your folder, after checking that each still carried the ETag it read at the start.</p>
          )}
          <dl className="mt-2 grid gap-3">
            <Etag title="Archive ETag" value={imp.archive.etag} label="archive ETag" />
            <Etag title="Manifest ETag" value={imp.manifest.etag} label="manifest ETag" />
          </dl>
        </Card>
      )
    }
    return (
      <Card icon={Archive} tone="text-accent" title="Archive kept in MinIO">
        <p>{`${inNexus(imp)} The archive stays in MinIO. Its reason:`}</p>
        <p className="rounded-md border border-line bg-background p-3 text-sm [overflow-wrap:anywhere]">{a.removal.reason || "Not recorded"}</p>
        <p className="text-muted">
          Retry adds an attempt: it checks every package again and removes the archive only if both objects still carry the ETags this import read. An archive replaced since is refused.
        </p>
        <RetryAction imp={imp} />
      </Card>
    )
  }
  if (a.outcome === "refused") {
    const reason = a.report.reason
    return (
      <Card icon={ShieldX} tone="text-severity-critical-fg" panel="border-severity-critical/40 bg-severity-critical/10" title="Refused before the first package">
        <p className="[overflow-wrap:anywhere]">{reason || "Not recorded"}</p>
        <p>This attempt published nothing and read no package.</p>
        <div className="mt-2">
          <Link to="/" className="inline-flex h-9 items-center gap-2 rounded-md bg-accent px-4 text-sm font-medium text-background outline-none hover:opacity-90 focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2">
            <Archive aria-hidden className="size-4" />
            Go to archives
          </Link>
        </div>
      </Card>
    )
  }
  if (a.outcome === "interrupted") {
    const c = counts(a)
    const unfinished = c.notFinished + c.pending
    return (
      <Card icon={CirclePause} tone="text-severity-high" title={`Stopped before it ended, ${a.endedAt ? `at ${formatWhen(a.endedAt)}` : "Not recorded"}`}>
        <p>The service stopped or restarted before this attempt ended.</p>
        <p>{`${c.done} of ${c.total} packages were finished. ${unfinished} were not finished, counted apart from failures.`}</p>
      </Card>
    )
  }
  return null
}
