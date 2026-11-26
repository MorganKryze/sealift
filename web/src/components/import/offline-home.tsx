import { ArchiveRestore, ChevronDown, ChevronUp, CircleCheck, CircleDashed, CircleX, Clock, LoaderCircle } from "lucide-react"
import { Fragment, type ReactNode, type Ref, useEffect, useId, useRef, useState } from "react"

import { EmptyGroup, GROUP_ROWS, type HomeRow, PathCard, RowGroup } from "@/components/home/blocks"
import { ApiFailure } from "@/components/import/api-failure"
import { crossingLabel, folderLabel, HomeArchiveRow, HomeLine, localDay } from "@/components/import/archive-row"
import { Button } from "@/components/ui/button"
import { useArchives, useImports, useMe, type Archive, type Import } from "@/import/api/queries"
import { archiveName, counts, FOLDERS, latestAttempt, whereText } from "@/import/lib/outcome"

/** The greeting for the local part of the day: morning until noon, afternoon until 18:00, then evening. */
export function greeting(now: Date, user?: string): string {
  const hour = now.getHours()
  const part = hour < 12 ? "morning" : hour < 18 ? "afternoon" : "evening"
  return user ? `Good ${part}, ${user}` : `Good ${part}`
}

const ended = (imp: Import) => latestAttempt(imp).endedAt ?? imp.createdAt
const time = (value: string) => Date.parse(value)
const plural = (n: number, one: string) => `${n.toLocaleString("en-US")} ${n === 1 ? one : `${one}s`}`

/** The times of each project's crossings, by project and local day, so a second crossing of the day reads "· 2". */
function crossingDays(entries: { project?: string; at: string }[]): (project: string | undefined, at: string) => string[] {
  const days = new Map<string, string[]>()
  const keyOf = (project: string, at: string) => `${project}\u0000${localDay(at)}`
  for (const { project, at } of entries) {
    if (!project) continue
    const key = keyOf(project, at)
    days.set(key, [...(days.get(key) ?? []), at])
  }
  return (project, at) => (project ? (days.get(keyOf(project, at)) ?? []) : [])
}

/** The project an import's latest report names from its signed manifest. */
const projectOf = (imp: Import) => latestAttempt(imp).report.crossing?.project

interface Placed {
  key: string
  when: string
  row: HomeRow
}

/** What an import says on the home, or nothing when its row belongs to its archive or to no group. */
function importRow(imp: Import, name: string, newer: boolean, midnight: Date): { group: "needs" | "progress" | "done"; placed: Placed } | null {
  const open = { label: "Open", to: `/imports/${encodeURIComponent(imp.id)}` }
  const attempt = latestAttempt(imp)
  const c = counts(attempt)
  const placed = (when: string, row: Omit<HomeRow, "key" | "name" | "action">): Placed => ({ key: imp.id, when, row: { key: imp.id, name, action: open, ...row } })
  switch (imp.outcome) {
    case "queued":
      return { group: "progress", placed: placed(imp.createdAt, { icon: Clock, detail: "Waiting its turn", state: { label: "Queued", tone: "info" } }) }
    case "running":
      return {
        group: "progress",
        placed: placed(imp.createdAt, { icon: LoaderCircle, detail: c.total > 0 ? `${c.done.toLocaleString("en-US")} of ${plural(c.total, "package")}` : "Reading the manifest", state: { label: "Importing", tone: "info" } }),
      }
    case "incomplete":
    case "interrupted":
    case "cancelled": {
      // A later import of the same archive takes over: the user started again from there.
      if (newer) return null
      const missing = c.failed + c.notFinished + c.pending
      const detail = missing > 0 ? `${plural(missing, "package")} not in Nexus` : attempt.report.reason || "Reason not recorded"
      if (imp.outcome === "cancelled") return { group: "needs", placed: placed(ended(imp), { icon: CircleDashed, detail, state: { label: "Cancelled", tone: "warn" } }) }
      return { group: "needs", placed: placed(ended(imp), { icon: CircleX, detail: imp.outcome === "interrupted" ? `Interrupted, ${detail}` : detail, state: { label: "Failed", tone: "bad" } }) }
    }
    case "complete":
      if (time(ended(imp)) < midnight.getTime()) return null
      return { group: "done", placed: placed(ended(imp), { icon: CircleCheck, detail: `${plural(c.published + c.present, "package")} in Nexus`, state: { label: "Done", tone: "ok" } }) }
    default:
      // A refusal reads on its archive's row while the archive stays in the folder.
      return null
  }
}

/** A Needs you row: an import that needs the user, or an archive of the folder; urgent rows come first. */
interface NeedsRow {
  key: string
  when: string
  urgent: boolean
  draw: (actionRef?: Ref<HTMLAnchorElement>) => ReactNode
}

/** What an archive of the folder asks of the user, or nothing when one of its imports speaks for it. */
function archiveRow(archive: Archive, imports: Map<string, Import>, sameDay: (project: string | undefined, at: string) => string[], shared: boolean): NeedsRow | null {
  const latest = archive.latestImport ? imports.get(archive.latestImport.id) : undefined
  const outcome = latest?.outcome ?? archive.latestImport?.outcome
  if (outcome && outcome !== "refused") return null
  const project = archive.signature === "verified" ? archive.crossing?.project : undefined
  const rank = { project, sameDay: sameDay(project, archive.modified) }
  const refusal =
    archive.importable && archive.latestImport && outcome === "refused"
      ? { reason: (latest ? latestAttempt(latest).report.reason : "") || "Reason not recorded", to: `/imports/${encodeURIComponent(archive.latestImport.id)}` }
      : undefined
  return {
    key: archive.key,
    when: archive.modified,
    urgent: !archive.importable || refusal !== undefined,
    draw: (actionRef) => <HomeArchiveRow key={archive.key} archive={archive} rank={rank} shared={shared} refusal={refusal} actionRef={actionRef} />,
  }
}

const newestFirst = <T extends { when: string }>(rows: T[]) => [...rows].sort((a, b) => time(b.when) - time(a.when))

/** Needs you: refused and failed rows first, then the archives to import, newest first in each; the first 10, then Show all in place. */
function NeedsYou({ rows }: { rows: NeedsRow[] }) {
  const id = useId()
  const [all, setAll] = useState(false)
  // The control that showed the rest stays, so focus moves to the first row it showed.
  const moveFocus = useRef(false)
  const ordered = [...newestFirst(rows.filter((r) => r.urgent)), ...newestFirst(rows.filter((r) => !r.urgent))]
  const shown = all ? ordered : ordered.slice(0, GROUP_ROWS)
  const list = useRef<HTMLUListElement>(null)
  useEffect(() => {
    if (moveFocus.current) {
      moveFocus.current = false
      list.current?.children[GROUP_ROWS]?.querySelector<HTMLAnchorElement>("a")?.focus()
    }
  }, [all])
  return (
    <section aria-labelledby={id} className="mt-10">
      <h2 id={id} className="border-b border-rule pb-2 text-sm font-medium text-ink-2">
        Needs you
      </h2>
      <ul ref={list} className="flex flex-col">{shown.map((row) => <Fragment key={row.key}>{row.draw()}</Fragment>)}</ul>
      {ordered.length > GROUP_ROWS ? (
        <Button
          variant="outline"
          className="mt-4"
          aria-expanded={all}
          onClick={() => {
            moveFocus.current = !all
            setAll(!all)
          }}
        >
          {all ? <ChevronUp aria-hidden="true" /> : <ChevronDown aria-hidden="true" />}
          {all ? "Show fewer" : `Show all ${plural(ordered.length, "archive")}`}
        </Button>
      ) : null}
    </section>
  )
}

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
  const sameDayImport = crossingDays(records.map((imp) => ({ project: projectOf(imp), at: imp.createdAt })))
  const nameOf = (imp: Import) => {
    const project = projectOf(imp)
    return project ? crossingLabel(project, imp.createdAt, sameDayImport(project, imp.createdAt)) : folderLabel(imp.archive.key)
  }
  const groups: Record<"progress" | "done", Placed[]> = { progress: [], done: [] }
  const needs: NeedsRow[] = []
  for (const imp of records) {
    const newer = records.some((other) => other.archive.key === imp.archive.key && time(other.createdAt) > time(imp.createdAt))
    const placed = importRow(imp, nameOf(imp), newer, midnight)
    if (!placed) continue
    if (placed.group === "needs") {
      const { key, ...line } = placed.placed.row
      needs.push({ key, when: placed.placed.when, urgent: true, draw: (actionRef) => <HomeLine key={key} {...line} mono={!projectOf(imp)} actionRef={actionRef} /> })
    } else groups[placed.group].push(placed.placed)
  }
  const folderOf = (archive: Archive) => archiveName(archive.key).folder
  const archivesIn = new Map<string, number>()
  for (const archive of list?.archives ?? []) archivesIn.set(folderOf(archive), (archivesIn.get(folderOf(archive)) ?? 0) + 1)
  const sameDayArchive = crossingDays((list?.archives ?? []).map((a) => ({ project: a.signature === "verified" ? a.crossing?.project : undefined, at: a.modified })))
  for (const archive of list?.archives ?? []) {
    const row = archiveRow(archive, byId, sameDayArchive, (archivesIn.get(folderOf(archive)) ?? 0) > 1)
    if (row) needs.push(row)
  }
  const nothing = needs.length + groups.progress.length + groups.done.length === 0
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
            <NeedsYou rows={needs} />
          )}
          <RowGroup title="In progress" rows={newestFirst(groups.progress).map((p) => p.row)} noun={["import", "imports"]} />
          <RowGroup title="Done today" rows={newestFirst(groups.done).map((p) => p.row)} noun={["import", "imports"]} />
        </>
      )}
    </div>
  )
}
