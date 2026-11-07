import { Link } from "@tanstack/react-router"
import { Inbox } from "lucide-react"

import { ApiFailure } from "@/components/import/api-failure"
import { useImports, useMe } from "@/import/api/queries"

import { ImportRow } from "./import-row"

const choose =
  "inline-flex h-9 items-center rounded-md bg-accent px-4 text-sm font-medium text-background outline-none hover:opacity-90 focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 focus-visible:ring-offset-background"

function plural(n: number, one: string, many: string) {
  return n === 1 ? one : many
}

/** The user's imports, newest first, with one status region that stays mounted from load to list. */
export function ImportsList() {
  const query = useImports()
  const me = useMe()
  const imports = query.data
    ? [...query.data.imports].sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt) || b.id.localeCompare(a.id))
    : undefined
  const running = imports?.filter((i) => i.outcome === "running").length ?? 0
  const queued = imports?.filter((i) => i.outcome === "queued").length ?? 0

  return (
    <>
      <div role="status" className="mt-7 mb-3 flex min-h-5 flex-wrap items-center gap-x-2 text-sm">
        {query.isPending ? (
          <span className="text-muted">Loading your imports</span>
        ) : imports && imports.length > 0 ? (
          <>
            <span>
              <b className="font-mono font-semibold">{imports.length}</b> {plural(imports.length, "import", "imports")}
            </span>
            {running > 0 ? (
              <span>
                <span aria-hidden className="text-muted">· </span>
                <b className="font-mono font-semibold">{running}</b> running
              </span>
            ) : null}
            {queued > 0 ? (
              <span>
                <span aria-hidden className="text-muted">· </span>
                <b className="font-mono font-semibold">{queued}</b> queued
              </span>
            ) : null}
            {running + queued > 0 ? <span className="text-muted">One import runs at a time; the others wait in the order they were started.</span> : null}
            {query.isError ? <span className="text-severity-critical-fg">The last refresh failed. The list is as it was.</span> : null}
          </>
        ) : null}
      </div>
      {query.isPending ? (
        <div aria-hidden className="overflow-hidden rounded-xl border border-line">
          {[0, 1, 2, 3].map((n) => (
            <div key={n} className="grid min-h-18 grid-cols-[minmax(0,1fr)_128px_288px_16px] items-center gap-5 border-t border-line px-5 py-4 first:border-t-0">
              <div>
                <div className="h-3.5 w-3/5 rounded bg-line" />
                <div className="mt-2 h-3 w-2/5 rounded bg-line" />
              </div>
              <div className="h-6 w-24 rounded-full bg-line" />
              <div className="h-3.5 w-2/3 rounded bg-line" />
              <span />
            </div>
          ))}
        </div>
      ) : imports === undefined ? (
        <ApiFailure error={query.error} onRetry={() => void query.refetch()} untouched="Your archives in MinIO are untouched." />
      ) : imports.length === 0 ? (
        <div className="mt-8 flex flex-col items-center rounded-xl border border-dashed border-line px-8 py-12 text-center">
          <div className="flex size-11 items-center justify-center rounded-full border border-line bg-card text-muted">
            <Inbox aria-hidden className="size-5" />
          </div>
          <h2 className="mt-4 text-lg font-semibold">No import yet</h2>
          <p className="mt-1.5 mb-5 max-w-[52ch] leading-6 text-muted">
            An import starts from an archive in your MinIO folder{" "}
            <code className="rounded border border-line bg-card px-1.5 py-px font-mono text-[12.5px] text-ink [overflow-wrap:anywhere]">
              {me.data ? `${me.data.bucket}/${me.data.folder}` : "packages/npm/"}
            </code>
            . Once you start one, it appears here with its progress and its report.
          </p>
          <Link to="/" className={choose}>
            Choose an archive
          </Link>
        </div>
      ) : (
        <ul className="overflow-hidden rounded-xl border border-line">
          {imports.map((imp) => (
            <ImportRow key={imp.id} imp={imp} />
          ))}
        </ul>
      )}
    </>
  )
}
