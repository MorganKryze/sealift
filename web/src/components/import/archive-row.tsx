import { Link } from "@tanstack/react-router"
import { useRef, useState } from "react"

import { Button } from "@/components/ui/button"
import type { Archive } from "@/import/api/queries"
import { archiveName, counts, latestAttempt, type Import } from "@/import/lib/outcome"
import { formatBytes, formatWhen } from "@/lib/utils"

import { ConfirmPanel } from "./confirm-panel"
import { Figures } from "./import-row"
import { OutcomeBadge } from "./outcome-badge"

const clamp = "line-clamp-2 [overflow-wrap:anywhere]"
const action =
  "inline-flex h-8 items-center justify-center rounded-md border border-line bg-background px-3 text-sm font-medium text-ink outline-none hover:bg-card focus-visible:ring-2 focus-visible:ring-accent"

interface ArchiveRowProps {
  archive: Archive
  /** The full record of the archive's latest import, when the imports list has it. */
  latest?: Import
  /** The user's own queued or running import, which the new one would wait for. */
  ownActive?: Import
}

/** One archive of the folder: its name, whether it can be imported, what its latest import did and the one action that follows. */
export function ArchiveRow({ archive, latest, ownActive }: ArchiveRowProps) {
  const [confirming, setConfirming] = useState(false)
  const actions = useRef<HTMLDivElement>(null)
  const { folder, file } = archiveName(archive.key)
  const known = archive.latestImport
  const outcome = known ? (latest?.outcome ?? known.outcome) : undefined
  const start = (
    <Button size="sm" aria-label={`Start import of ${folder}${file}`} aria-expanded={confirming} onClick={() => setConfirming(true)}>
      Start
    </Button>
  )
  return (
    <li className="grid min-h-18 grid-cols-[minmax(0,1fr)_288px_128px] items-center gap-5 border-t border-line px-5 py-4 first:border-t-0">
      <div className="min-w-0">
        <p title={file} className={`font-mono text-[13px] font-medium ${clamp}`}>
          {file}
        </p>
        <p className="mt-1 flex min-w-0 gap-2 text-xs text-muted">
          <span title={folder} className={`min-w-0 font-mono text-[11.5px] ${clamp}`}>
            {folder}
          </span>
          <span className="flex-none whitespace-nowrap before:mr-2 before:content-['·']">{formatBytes(archive.size)}</span>
          <time dateTime={archive.modified} className="flex-none whitespace-nowrap before:mr-2 before:content-['·']">
            {formatWhen(archive.modified)}
          </time>
        </p>
      </div>
      {archive.importable ? (
        <>
          <div className="min-w-0">
            <p className="mb-1 text-xs text-muted">Can be imported</p>
            {known && outcome ? <Latest outcome={outcome} latest={latest} /> : <p className="text-[13px]">Not imported yet</p>}
          </div>
          <div ref={actions} className="justify-self-end">
            {known && outcome ? <Next id={known.id} outcome={outcome} label={`${folder}${file}`} start={start} /> : start}
          </div>
          {confirming ? (
            <ConfirmPanel
              archive={archive}
              ownActive={ownActive}
              onClose={() => {
                setConfirming(false)
                actions.current?.querySelector("button")?.focus()
              }}
            />
          ) : null}
        </>
      ) : (
        <div className="col-span-2 min-w-0">
          <p className="text-[13px] font-medium">Cannot be imported</p>
          <p className="mt-1 text-[13px] [overflow-wrap:anywhere]">{archive.reason || "Reason not recorded"}</p>
          <p className="mt-1 text-xs text-muted">Keep one archive and its manifest.json side by side, at the root of packages/npm/ or one folder below.</p>
        </div>
      )}
    </li>
  )
}

function Next({ id, outcome, label, start }: { id: string; outcome: string; label: string; start: React.ReactNode }) {
  switch (outcome) {
    case "queued":
    case "running":
      return (
        <Link to="/imports/$importId" params={{ importId: id }} aria-label={`Follow the import of ${label}`} className={action}>
          Follow
        </Link>
      )
    case "incomplete":
    case "interrupted":
      return (
        <Link to="/imports/$importId" params={{ importId: id }} aria-label={`Open import of ${label}`} className={action}>
          Open import
        </Link>
      )
    default:
      return start
  }
}

function Latest({ outcome, latest }: { outcome: string; latest?: Import }) {
  const attempt = latest ? latestAttempt(latest) : undefined
  const c = attempt ? counts(attempt) : undefined
  return (
    <div>
      <OutcomeBadge outcome={outcome} />
      {attempt && c ? (
        outcome === "running" ? (
          <p className="mt-1.5 text-xs text-muted">{c.total > 0 ? `${c.done} of ${c.total} packages` : "Reading the manifest"}</p>
        ) : outcome === "queued" ? (
          <p className="mt-1.5 text-xs text-muted">Waiting its turn</p>
        ) : outcome === "refused" ? (
          <p className={`mt-1.5 text-xs text-muted ${clamp}`}>{attempt.report.reason || "Reason not recorded"}</p>
        ) : (
          <div className="mt-1.5">
            <Figures attempt={attempt} />
          </div>
        )
      ) : null}
      {outcome === "complete" && attempt ? <p className={`mt-1.5 text-xs text-muted ${clamp}`}>{kept(attempt.removal)}</p> : null}
    </div>
  )
}

/** A complete import whose archive is still listed. Only a recorded removal that failed says why the archive stayed. */
function kept(removal: { removed: boolean; reason: string } | undefined): string {
  if (!removal) {
    return "Removal not recorded yet."
  }
  if (removal.removed) {
    return "Recorded as removed, yet still listed."
  }
  return `Kept in MinIO: ${removal.reason || "Not recorded"}`
}
