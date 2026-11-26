import { Link } from "@tanstack/react-router"
import { Check, ChevronDown, CircleDashed, CircleX, FileArchive, type LucideIcon, ShieldCheck } from "lucide-react"
import { type ReactNode, type Ref, useId, useRef, useState } from "react"

import { Button } from "@/components/ui/button"
import type { Archive } from "@/import/api/queries"
import { archiveName, counts, ecosystemOf, FOLDERS, latestAttempt, type Import } from "@/import/lib/outcome"
import { cn, formatBytes, formatWhen } from "@/lib/utils"

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
  /** Opens the row with its confirmation showing, as when the home's Import led here. */
  confirmOpen?: boolean
}

/** One archive of the folder: its name, whether it can be imported, what its latest import did and the one action that follows. */
export function ArchiveRow({ archive, latest, ownActive, confirmOpen = false }: ArchiveRowProps) {
  const [confirming, setConfirming] = useState(confirmOpen)
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
    <li className="grid min-h-18 grid-cols-[minmax(0,1fr)] items-center gap-3 md:grid-cols-[minmax(0,1fr)_288px_128px] md:gap-5 border-t border-line px-5 py-4 first:border-t-0">
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
          <div ref={actions} className="md:justify-self-end">
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
        <div className="min-w-0 md:col-span-2">
          <p className="text-[13px] font-medium">Cannot be imported</p>
          <p className="mt-1 text-[13px] [overflow-wrap:anywhere]">{archive.reason || "Reason not recorded"}</p>
          <p className="mt-1 text-xs text-muted">Keep one archive with its manifest.json and manifest.json.sig side by side, in packages/npm/ for npm or packages/pip/ for pip, at the root or one folder below. sealift 0.4.0 and earlier wrote no manifest.json.sig: export such an archive again.</p>
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

const DAY_MS = 86_400_000
const plural = (n: number, one: string) => `${n.toLocaleString("en-US")} ${n === 1 ? one : `${one}s`}`

/** When an archive came in, in words: minutes, hours today, yesterday, days within the week, then the day. */
export function uploaded(modified: string, now: Date): string {
  const at = new Date(modified)
  const minutes = Math.floor((now.getTime() - at.getTime()) / 60_000)
  if (minutes < 1) return "uploaded less than a minute ago"
  if (minutes < 60) return `uploaded ${plural(minutes, "minute")} ago`
  const midnight = new Date(now.getFullYear(), now.getMonth(), now.getDate())
  if (at >= midnight) return `uploaded ${plural(Math.floor(minutes / 60), "hour")} ago`
  const days = Math.ceil((midnight.getTime() - new Date(at.getFullYear(), at.getMonth(), at.getDate()).getTime()) / DAY_MS)
  if (days <= 1) return "uploaded yesterday"
  if (days < 7) return `uploaded ${days} days ago`
  return `uploaded ${dayOf(at, now)}`
}

/** The local day in en-GB, "25 Nov", with the year when it is not this year's. */
function dayOf(at: Date, now: Date): string {
  const year = at.getFullYear() === now.getFullYear() ? {} : { year: "numeric" as const }
  return new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "short", ...year }).format(at)
}

/** The local day a time falls on, as a key that groups the crossings of one day. */
export const localDay = (at: string) => {
  const d = new Date(at)
  return `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`
}

/**
 * A crossing's name: the project, then the local day it reached this side, "web-portal · 25 Nov". The second crossing of the
 * project that day takes "· 2", and on; sameDay holds the times of that project's crossings that day.
 */
export function crossingLabel(project: string, at: string, sameDay: string[]): string {
  const name = `${project} · ${dayOf(new Date(at), new Date())}`
  const n = [...sameDay].sort((a, b) => Date.parse(a) - Date.parse(b)).indexOf(at) + 1
  return n > 1 ? `${name} · ${n}` : name
}

/** An archive named by its place: its folder with its slash, its file at an ecosystem's root, or both when the folder holds another. */
export function folderLabel(key: string, shared = false): string {
  const { folder, file } = archiveName(key)
  if ((FOLDERS as readonly string[]).includes(folder) || folder === "") return file
  return shared ? `${folder}${file}` : folder
}

/** Files, signature, folder and the size the signed manifest states all pass: the Compliant chip shows. */
export function isCompliant(archive: Archive): boolean {
  return archive.importable && archive.signature === "verified" && archive.declaredSize !== undefined && archive.declaredSize === archive.size && archive.files?.length === 3
}

export type Tone = "ok" | "warn" | "bad" | "info"

// A failed row is tinted red itself, so its icon box and chip sit on the page colour to stand out.
const BOX: Record<Tone, string> = {
  ok: "tinted-ok text-ok",
  warn: "tinted-warn text-warn",
  bad: "tinted-bad bg-bg text-bad",
  info: "tinted-info text-info",
}

const lineAction = "min-w-21 max-sm:h-11"

interface HomeLineProps {
  icon: LucideIcon
  name: string
  /** A folder's name is data, in the monospaced face. */
  mono?: boolean
  state?: { label: string; tone: Tone }
  detail: ReactNode
  action: { label: string; to: string; search?: Record<string, string> }
  actionRef?: Ref<HTMLAnchorElement>
  /** What sits before the action, such as the Compliant chip. */
  aside?: ReactNode
  /** What opens under the row. */
  children?: ReactNode
}

/** One row of the Offline home: its icon, its name, its state and facts, then its action. A failed row is closed and tinted red. */
export function HomeLine({ icon: Icon, name, mono, state, detail, action, actionRef, aside, children }: HomeLineProps) {
  const failed = state?.tone === "bad"
  return (
    <li className={cn("flex flex-wrap items-center gap-x-3 gap-y-2 py-3", failed ? "tinted-bad -mx-3 my-1 px-3" : "border-b border-rule")}>
      <span className={cn("grid size-8 flex-none place-items-center rounded-lg", state ? BOX[state.tone] : "bg-hover text-ink-2")}>
        <Icon aria-hidden="true" className="size-4" />
      </span>
      <div className="min-w-0 flex-1">
        <p data-row-name="" className={cn("text-ink [overflow-wrap:anywhere]", mono ? "font-mono text-[13.5px] font-medium" : "font-semibold")}>
          {name}
        </p>
        <p className="mt-0.5 flex flex-wrap items-center gap-x-1.5 gap-y-1 text-sm text-muted [overflow-wrap:anywhere]">
          {state ? <span className={cn("inline-flex w-fit items-center !rounded-full px-2 text-[13px] font-medium", BOX[state.tone])}>{state.label}</span> : null}
          <span>{detail}</span>
        </p>
      </div>
      <div className="flex flex-wrap items-center gap-2.5">
        {aside}
        <Button asChild variant="outline" className={lineAction}>
          <Link to={action.to} search={action.search} aria-label={`${action.label} ${name}`} ref={actionRef}>
            {action.label}
          </Link>
        </Button>
      </div>
      {children}
    </li>
  )
}

interface HomeArchiveRowProps {
  archive: Archive
  /** The project its verified manifest names, and the times of that project's crossings that reached the folder the same day. */
  rank: { project?: string; sameDay: string[] }
  /** The folder holds another archive, so the name keeps the file. */
  shared?: boolean
  /** Why its latest import was refused, and where Open leads. */
  refusal?: { reason: string; to: string }
  actionRef?: Ref<HTMLAnchorElement>
}

/**
 * An archive of the folder on the Offline home: named by its crossing once its signature verifies, else by its folder; its
 * facts; the Compliant chip and its checks, or Not checked yet; or the refused row with its reason and Open.
 */
export function HomeArchiveRow({ archive, rank, shared = false, refusal, actionRef }: HomeArchiveRowProps) {
  const [open, setOpen] = useState(false)
  const checksId = useId()
  const captionId = useId()
  const verified = archive.signature === "verified"
  const name = verified && rank.project ? crossingLabel(rank.project, archive.modified, rank.sameDay) : folderLabel(archive.key, shared)
  const mono = !(verified && rank.project)
  const refused = refusal ?? (archive.importable ? undefined : { reason: archive.reason || "Reason not recorded", to: "/import" })
  if (refused) {
    return <HomeLine icon={CircleX} name={name} mono={mono} state={{ label: "Refused", tone: "bad" }} detail={refused.reason} action={{ label: "Open", to: refused.to }} actionRef={actionRef} />
  }
  const eco = archive.ecosystem ?? ecosystemOf(archive.key)
  const packages = verified ? archive.crossing?.packages : undefined
  const detail = (
    <>
      {`${eco} · `}
      {packages !== undefined ? (
        <>
          <b className="font-semibold text-ink-2">{packages.toLocaleString("en-US")}</b>
          {packages === 1 ? " package · " : " packages · "}
        </>
      ) : null}
      <b className="font-semibold text-ink-2">{formatBytes(archive.size)}</b>
      {` · ${uploaded(archive.modified, new Date())}`}
    </>
  )
  const compliant = isCompliant(archive)
  const aside = compliant ? (
    <button
      type="button"
      aria-expanded={open}
      aria-controls={checksId}
      onClick={() => setOpen((o) => !o)}
      className="inline-flex h-8 items-center gap-1.5 rounded-full px-3 text-[13px] font-semibold tinted-ok text-ok transition-[transform] duration-160 ease-out motion-safe:active:scale-[0.97]"
    >
      <ShieldCheck aria-hidden="true" className="size-4" />
      Compliant
      <ChevronDown aria-hidden="true" className={cn("size-4 transition-transform duration-200 ease-out motion-reduce:transition-none", open && "rotate-180")} />
    </button>
  ) : verified ? null : (
    <span className="text-[13px] text-muted">Not checked yet</span>
  )
  const { folder } = archiveName(archive.key)
  const root = FOLDERS.find((f) => archive.key.startsWith(f)) ?? ""
  return (
    <HomeLine icon={FileArchive} name={name} mono={mono} detail={detail} action={{ label: "Import", to: "/import", search: { start: archive.key } }} actionRef={actionRef} aside={aside}>
      {compliant && open ? (
        <div id={checksId} className="animate-fade basis-full pb-1 pl-11">
          <p id={captionId} className="text-xs font-semibold text-muted">
            3 checks passed
          </p>
          <ul aria-labelledby={captionId}>
            <CheckLine passed label="Files">
              <span className="font-mono text-ink-2">{folder}</span> holds the archive, its manifest and its signature
            </CheckLine>
            <CheckLine passed label="Signature">
              Ed25519, by the key this side trusts
            </CheckLine>
            <CheckLine passed label="Folder">
              {`${eco === "npm" ? "an npm" : `a ${eco}`} manifest, in `}
              <span className="font-mono text-ink-2">{root}</span>
            </CheckLine>
            <CheckLine label="Contents">sha256 and sha512, checked when the import starts</CheckLine>
          </ul>
        </div>
      ) : null}
    </HomeLine>
  )
}

function CheckLine({ passed = false, label, children }: { passed?: boolean; label: string; children: ReactNode }) {
  return (
    <li className="grid min-h-8.5 grid-cols-[16px_92px_minmax(0,1fr)] items-center gap-2.5 text-[13px]">
      {passed ? <Check aria-hidden="true" className="size-4 text-ok" /> : <CircleDashed aria-hidden="true" className="size-4 text-muted" />}
      <span className={cn("font-semibold", !passed && "text-muted")}>{label}</span>
      <span className="min-w-0 text-muted [overflow-wrap:anywhere]">{children}</span>
    </li>
  )
}
