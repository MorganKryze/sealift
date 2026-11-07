import { RefreshCw, Inbox } from "lucide-react"
import { useState } from "react"

import { ApiFailure } from "@/components/import/api-failure"
import { Button } from "@/components/ui/button"
import { ImportApiError } from "@/import/api/client"
import { useArchives, useImports, useMe, type Archive } from "@/import/api/queries"

import { ArchiveRow } from "./archive-row"
import { ImportFailure } from "./import-failure"
import { ListFilter } from "./list-filter"
import { ListNotices } from "./list-notices"

const code = "rounded border border-line bg-background px-1.5 py-px font-mono text-[12.5px] text-ink [overflow-wrap:anywhere]"

/** Newest modification first; equal times fall back to the key so the order never shifts between reads. */
function newestFirst(archives: Archive[]): Archive[] {
  return [...archives].sort((a, b) => Date.parse(b.modified) - Date.parse(a.modified) || a.key.localeCompare(b.key))
}

/** The archives of the user's folder, with one status region that stays mounted from load to list. */
export function ArchivesList() {
  const query = useArchives()
  const imports = useImports()
  const me = useMe()
  const [filter, setFilter] = useState<"all" | "importable">("all")
  const list = query.data
  const where = me.data ? `${me.data.bucket}/${me.data.folder}` : "packages/npm/"
  const refresh = () => void Promise.all([query.refetch(), imports.refetch()])

  const ownActive = imports.data?.imports.find((i) => i.outcome === "queued" || i.outcome === "running")
  const all = list ? newestFirst(list.archives) : []
  const importable = all.filter((a) => a.importable)
  const shown = filter === "importable" ? importable : all

  return (
    <>
      <div role="status" className="mt-7 mb-3 flex min-h-8 flex-wrap items-center justify-between gap-x-4 gap-y-2 text-sm">
        <span>
          {query.isPending ? (
            <span className="text-muted">Reading your folder in MinIO: {where}</span>
          ) : list && list.archives.length > 0 ? (
            <>
              <b className="font-mono font-semibold">{all.length}</b> {all.length === 1 ? "archive" : "archives"}
              <span aria-hidden className="text-muted"> · </span>
              <b className="font-mono font-semibold">{importable.length}</b> importable
              {query.isFetching ? <span className="text-muted"> · Refreshing</span> : null}
              {query.isError ? <span className="text-severity-critical-fg"> · The last refresh failed. The list is as it was.</span> : null}
            </>
          ) : null}
        </span>
        {list && list.archives.length > 0 ? (
          <span className="flex items-center gap-3">
            <ListFilter value={filter} onChange={setFilter} counts={{ all: all.length, importable: importable.length }} />
            <Button variant="outline" size="sm" onClick={refresh}>
              <RefreshCw aria-hidden />
              Refresh
            </Button>
          </span>
        ) : null}
      </div>
      {query.isPending ? (
        <div aria-hidden className="overflow-hidden rounded-xl border border-line">
          {[0, 1, 2, 3].map((n) => (
            <div key={n} className="grid min-h-18 grid-cols-[minmax(0,1fr)_288px_128px] items-center gap-5 border-t border-line px-5 py-4 first:border-t-0">
              <div>
                <div className="h-3.5 w-3/5 rounded bg-line" />
                <div className="mt-2 h-3 w-2/5 rounded bg-line" />
              </div>
              <div className="h-3.5 w-2/3 rounded bg-line" />
              <div className="h-8 w-16 justify-self-end rounded-md bg-line" />
            </div>
          ))}
        </div>
      ) : list === undefined ? (
        query.error instanceof ImportApiError && query.error.status === 502 ? (
          <ImportFailure
            title="The archives could not be listed"
            cause={query.error.problem?.detail ?? "MinIO failed."}
            next="Try again. Imports already started go on without this list."
            detail={`${query.error.status} ${query.error.problem?.title ?? ""}`.trim()}
            onRetry={refresh}
          />
        ) : (
          <ApiFailure error={query.error} onRetry={refresh} untouched="Imports already started go on." />
        )
      ) : !list.minioConfigured ? (
        <Empty title="MinIO is not configured" onRefresh={refresh}>
          The import service has no MinIO to read your archives from. The administrator sets it in the settings file.
        </Empty>
      ) : list.bucketMissing ? (
        <Empty title="No archive in your folder" onRefresh={refresh}>
          <span className="block text-ink">{list.message ?? `MinIO has no bucket ${list.bucket} yet: nothing to list`}</span>
          Once it exists, upload an archive and its <code className={code}>manifest.json</code> side by side in <code className={code}>{where}</code>.
        </Empty>
      ) : list.archives.length === 0 ? (
        <Empty title="No archive in your folder" onRefresh={refresh}>
          Upload an archive and its <code className={code}>manifest.json</code> side by side in <code className={code}>{where}</code>, at the root or one folder below. Then refresh.
        </Empty>
      ) : (
        <>
          <ListNotices list={list} />
          {shown.length === 0 ? (
            <p className="rounded-xl border border-dashed border-line px-8 py-10 text-center text-muted">No archive can be imported. The rows under All say why.</p>
          ) : (
            <ul className="overflow-hidden rounded-xl border border-line">
              {shown.map((a) => (
                <ArchiveRow key={a.key} archive={a} latest={imports.data?.imports.find((i) => i.id === a.latestImport?.id)} ownActive={ownActive} />
              ))}
            </ul>
          )}
        </>
      )}
    </>
  )
}

function Empty({ title, onRefresh, children }: { title: string; onRefresh: () => void; children: React.ReactNode }) {
  return (
    <div className="mt-8 flex flex-col items-center rounded-xl border border-dashed border-line px-8 py-12 text-center">
      <div className="flex size-11 items-center justify-center rounded-full border border-line bg-card text-muted">
        <Inbox aria-hidden className="size-5" />
      </div>
      <h2 className="mt-4 text-lg font-semibold">{title}</h2>
      <p className="mt-1.5 mb-5 max-w-[56ch] leading-6 text-muted">{children}</p>
      <Button variant="outline" onClick={onRefresh}>
        <RefreshCw aria-hidden />
        Refresh
      </Button>
    </div>
  )
}
