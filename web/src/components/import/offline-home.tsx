import { ArchiveRestore, CircleCheck, CircleX, Clock, FileArchive, LoaderCircle } from "lucide-react"

import { EmptyGroup, type HomeRow, PathCard, RowGroup } from "@/components/home/blocks"
import { ApiFailure } from "@/components/import/api-failure"
import { useArchives, useImports, useMe, type Archive, type Import } from "@/import/api/queries"
import { archiveName, counts, ecosystemOf, FOLDERS, latestAttempt, whereText } from "@/import/lib/outcome"
import { formatBytes } from "@/lib/utils"

/** The greeting for the local part of the day: morning until noon, afternoon until 18:00, then evening. */
export function greeting(now: Date, user?: string): string {
  const hour = now.getHours()
  const part = hour < 12 ? "morning" : hour < 18 ? "afternoon" : "evening"
  return user ? `Good ${part}, ${user}` : `Good ${part}`
}

/** An archive's row name: its folder, its file at the root of an ecosystem's folder, or both when the folder holds another archive. */
function rowName(key: string, shared = false): string {
  const { folder, file } = archiveName(key)
  if ((FOLDERS as readonly string[]).includes(folder) || folder === "") return file
  return shared ? `${folder}${file}` : folder.replace(/\/$/, "")
}

const DAY_MS = 86_400_000
const plural = (n: number, one: string) => `${n.toLocaleString("en-US")} ${n === 1 ? one : `${one}s`}`

/** When an archive came in, in words: minutes, hours today, yesterday, days within the week, then the day. */
function uploaded(modified: string, now: Date): string {
  const at = new Date(modified)
  const minutes = Math.floor((now.getTime() - at.getTime()) / 60_000)
  if (minutes < 1) return "uploaded less than a minute ago"
  if (minutes < 60) return `uploaded ${plural(minutes, "minute")} ago`
  const midnight = new Date(now.getFullYear(), now.getMonth(), now.getDate())
  if (at >= midnight) return `uploaded ${plural(Math.floor(minutes / 60), "hour")} ago`
  const days = Math.ceil((midnight.getTime() - new Date(at.getFullYear(), at.getMonth(), at.getDate()).getTime()) / DAY_MS)
  if (days <= 1) return "uploaded yesterday"
  if (days < 7) return `uploaded ${days} days ago`
  const year = at.getFullYear() === now.getFullYear() ? {} : { year: "numeric" as const }
  return `uploaded ${new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "short", ...year }).format(at)}`
}

const ended = (imp: Import) => latestAttempt(imp).endedAt ?? imp.createdAt
const time = (value: string) => Date.parse(value)

interface Placed {
  row: HomeRow
  when: string
}

/** What an import says on the home, or nothing when its row belongs to its archive or to no group. */
function importRow(imp: Import, newer: boolean, midnight: Date): { group: "needs" | "progress" | "done"; placed: Placed } | null {
  const name = rowName(imp.archive.key)
  const open = { label: "Open", to: `/imports/${encodeURIComponent(imp.id)}` }
  const attempt = latestAttempt(imp)
  const c = counts(attempt)
  switch (imp.outcome) {
    case "queued":
      return { group: "progress", placed: { when: imp.createdAt, row: { key: imp.id, icon: Clock, name, detail: "Waiting its turn", state: { label: "Queued", tone: "info" }, action: open } } }
    case "running":
      return {
        group: "progress",
        placed: { when: imp.createdAt, row: { key: imp.id, icon: LoaderCircle, name, detail: c.total > 0 ? `${c.done.toLocaleString("en-US")} of ${plural(c.total, "package")}` : "Reading the manifest", state: { label: "Importing", tone: "info" }, action: open } },
      }
    case "incomplete":
    case "interrupted": {
      // A later import of the same archive takes over: the user started again from there.
      if (newer) return null
      const missing = c.failed + c.notFinished
      const detail = missing > 0 ? `${plural(missing, "package")} not in Nexus` : attempt.report.reason || "Reason not recorded"
      return { group: "needs", placed: { when: ended(imp), row: { key: imp.id, icon: CircleX, name, detail: imp.outcome === "interrupted" ? `Interrupted, ${detail}` : detail, state: { label: "Failed", tone: "bad" }, action: open } } }
    }
    case "complete":
      if (time(ended(imp)) < midnight.getTime()) return null
      return { group: "done", placed: { when: ended(imp), row: { key: imp.id, icon: CircleCheck, name, detail: `${plural(c.published + c.present, "package")} in Nexus`, state: { label: "Done", tone: "ok" }, action: open } } }
    default:
      // A refusal reads on its archive's row while the archive stays in the folder.
      return null
  }
}

/** What an archive of the folder asks of the user, or nothing when one of its imports speaks for it. */
function archiveRow(archive: Archive, imports: Map<string, Import>, now: Date, shared: boolean): Placed | null {
  const name = rowName(archive.key, shared)
  const latest = archive.latestImport ? imports.get(archive.latestImport.id) : undefined
  const outcome = latest?.outcome ?? archive.latestImport?.outcome
  if (outcome && outcome !== "refused") return null
  const refused = (reason: string, to: string): Placed => ({
    when: archive.modified,
    row: { key: archive.key, icon: CircleX, name, detail: reason, state: { label: "Refused", tone: "bad" }, action: { label: "Open", to } },
  })
  if (!archive.importable) return refused(archive.reason || "Reason not recorded", "/import")
  if (archive.latestImport && outcome === "refused") {
    const reason = latest ? latestAttempt(latest).report.reason : ""
    return refused(reason || "Reason not recorded", `/imports/${encodeURIComponent(archive.latestImport.id)}`)
  }
  const detail = `${archive.ecosystem ?? ecosystemOf(archive.key)} · ${formatBytes(archive.size)} · ${uploaded(archive.modified, now)}`
  return { when: archive.modified, row: { key: archive.key, icon: FileArchive, name, detail, action: { label: "Import", to: "/import", search: { start: archive.key } } } }
}

const newestFirst = (rows: Placed[]) => [...rows].sort((a, b) => time(b.when) - time(a.when)).map((p) => p.row)

/** The Offline home: the greeting, the Import card, then what needs the user, what runs and what came in today. */
export function OfflineHome() {
  const me = useMe()
  const archives = useArchives(true)
  const imports = useImports()
  const now = new Date()
  const midnight = new Date(now.getFullYear(), now.getMonth(), now.getDate())

  const failure = archives.error ?? imports.error
  const list = archives.data
  const records = imports.data?.imports ?? []
  const byId = new Map(records.map((imp) => [imp.id, imp]))
  const groups: Record<"needs" | "progress" | "done", Placed[]> = { needs: [], progress: [], done: [] }
  for (const imp of records) {
    const newer = records.some((other) => other.archive.key === imp.archive.key && time(other.createdAt) > time(imp.createdAt))
    const placed = importRow(imp, newer, midnight)
    if (placed) groups[placed.group].push(placed.placed)
  }
  const folderOf = (archive: Archive) => archiveName(archive.key).folder
  const archivesIn = new Map<string, number>()
  for (const archive of list?.archives ?? []) archivesIn.set(folderOf(archive), (archivesIn.get(folderOf(archive)) ?? 0) + 1)
  for (const archive of list?.archives ?? []) {
    const placed = archiveRow(archive, byId, now, (archivesIn.get(folderOf(archive)) ?? 0) > 1)
    if (placed) groups.needs.push(placed)
  }
  const nothing = groups.needs.length + groups.progress.length + groups.done.length === 0
  const refresh = () => void Promise.all([archives.refetch(), imports.refetch()])

  return (
    <div className="animate-enter mx-auto w-full max-w-170">
      <h1 className="text-[28px] font-bold tracking-tight text-ink [overflow-wrap:anywhere]">{greeting(now, me.data?.user)}</h1>
      <div className="mt-6">
        <PathCard to="/import" icon={ArchiveRestore} title="Import" detail="an archive" lead />
      </div>

      {failure && !(list && imports.data) ? (
        <div className="mt-10">
          <ApiFailure error={failure} onRetry={refresh} untouched="Imports already started go on." />
        </div>
      ) : !list || !imports.data ? (
        <div role="status" className="tinted-info mt-10 flex w-fit items-center gap-2 px-3 py-2 text-sm text-info">
          <LoaderCircle aria-hidden="true" className="size-4 motion-safe:animate-spin" />
          {`Reading your folders in MinIO: ${whereText(me.data?.bucket)}`}
        </div>
      ) : (
        <>
          {list.message && !list.bucketMissing ? <p className="tinted-warn mt-10 px-3 py-2 text-sm text-ink [overflow-wrap:anywhere]">{list.message}</p> : null}
          {nothing ? (
            <EmptyGroup
              title="Needs you"
              text={list.minioConfigured ? `No archive in ${list.bucket}/${FOLDERS[0]} or ${FOLDERS[1]}` : "MinIO is not configured. The administrator sets it in the settings file."}
            />
          ) : (
            <RowGroup title="Needs you" rows={newestFirst(groups.needs)} noun={["archive or import", "archives and imports"]} />
          )}
          <RowGroup title="In progress" rows={newestFirst(groups.progress)} noun={["import", "imports"]} />
          <RowGroup title="Done today" rows={newestFirst(groups.done)} noun={["import", "imports"]} />
        </>
      )}
    </div>
  )
}
