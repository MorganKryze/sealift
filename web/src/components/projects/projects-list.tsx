import { Link } from "@tanstack/react-router"
import { ArrowDownAZ, Ban, ChevronRight, CircleAlert, CircleDashed, CircleX, Clock, FolderGit2, LoaderCircle, Lock, RefreshCw, RotateCw } from "lucide-react"
import { useState } from "react"

import type { ProjectSummary } from "@/api/projects"
import { EphemeralBanner } from "@/components/ephemeral"
import { Button } from "@/components/ui/button"
import { byName, crossingDay, type CrossingKind, crossingState, nameLetter } from "@/lib/crossings"
import { cn } from "@/lib/utils"

// Past this many, Latest shows the newest and a control for the rest.
const LATEST_ROWS = 15

const CHIP: Record<CrossingKind, { icon: typeof Lock; className: string }> = {
  sealed: { icon: Lock, className: "tinted-ok text-ok" },
  running: { icon: LoaderCircle, className: "tinted-info text-info [&>svg]:motion-safe:animate-spin" },
  queued: { icon: Clock, className: "tinted-info text-info" },
  waits: { icon: CircleAlert, className: "tinted-warn text-warn" },
  failed: { icon: CircleX, className: "tinted-bad bg-bg text-bad" },
  cancelled: { icon: Ban, className: "border border-rule-2 bg-hover text-ink-2" },
  new: { icon: CircleDashed, className: "border border-dashed border-field text-muted" },
}

const ICON_COLOUR: Record<CrossingKind, string> = {
  sealed: "text-ok",
  running: "text-info motion-safe:animate-spin",
  queued: "text-info",
  waits: "text-warn",
  failed: "text-bad",
  cancelled: "text-muted",
  new: "text-muted",
}

/** A crossing's state as its icon alone, in its state's colour, beside a chip that says it in words. */
export function StateIcon({ kind }: { kind: CrossingKind }) {
  const Icon = CHIP[kind].icon
  return <Icon aria-hidden="true" className={cn("size-5 flex-none", ICON_COLOUR[kind])} />
}

/** A crossing's state as a chip: its icon, its word and its state's colours. */
export function StateChip({ label, kind }: { label: string; kind: CrossingKind }) {
  const { icon: Icon, className } = CHIP[kind]
  return (
    <span className={cn("inline-flex w-fit items-center gap-1.5 rounded-full px-2 py-0.5 text-[13px] font-medium whitespace-nowrap", className)}>
      <Icon aria-hidden="true" className="size-3.5 flex-none" />
      {label}
    </span>
  )
}

export function EcosystemChip({ ecosystem }: { ecosystem: ProjectSummary["ecosystem"] }) {
  return <span className="inline-flex h-6 w-fit items-center rounded-md bg-hover px-1.5 text-xs font-medium text-ink-2">{ecosystem}</span>
}

/** The latest crossing's state; an export counts only when it belongs to the latest analysis. */
function summaryState(project: ProjectSummary) {
  const last = project.lastAnalysis
  const exported = last && project.lastExport?.analysisId === last.id ? project.lastExport : undefined
  return crossingState(last, exported)
}

const started = (project: ProjectSummary) => (project.lastAnalysis ? new Date(project.lastAnalysis.createdAt).getTime() : -Infinity)

const COLUMNS = "md:grid md:grid-cols-[minmax(0,1fr)_88px_150px_200px_16px] md:gap-x-4"

function ProjectRow({ project }: { project: ProjectSummary }) {
  const state = summaryState(project)
  const failed = state.kind === "failed"
  return (
    <li>
      <Link
        to="/projects/$projectId"
        params={{ projectId: project.id }}
        className={cn(
          "flex min-h-14 flex-wrap items-center gap-x-3 gap-y-1.5 px-3 py-3 text-ink transition-colors duration-150 [@media(hover:hover)_and_(pointer:fine)]:hover:bg-hover",
          COLUMNS,
          failed ? "tinted-bad my-1 [@media(hover:hover)_and_(pointer:fine)]:hover:bg-bad-tint" : "border-b border-rule",
        )}
      >
        <span className="basis-full font-semibold [overflow-wrap:anywhere] md:basis-auto">{project.name}</span>
        <EcosystemChip ecosystem={project.ecosystem} />
        {project.lastAnalysis ? (
          <>
            <span className="figure">{crossingDay(project.lastAnalysis.createdAt)}</span>
            <StateChip {...state} />
          </>
        ) : (
          <span className="md:col-span-2">
            <StateChip {...state} />
          </span>
        )}
        <ChevronRight aria-hidden="true" className="ml-auto size-4 flex-none text-faint md:ml-0" />
      </Link>
    </li>
  )
}

function Rows({ projects, label }: { projects: ProjectSummary[]; label?: string }) {
  return (
    <ul aria-label={label} className="flex flex-col">
      {projects.map((project) => (
        <ProjectRow key={project.id} project={project} />
      ))}
    </ul>
  )
}

type Order = "latest" | "name"

function OrderChoice({ order, onChange }: { order: Order; onChange: (order: Order) => void }) {
  const choice = (value: Order, label: string, Icon: typeof Clock) => (
    <button
      type="button"
      aria-pressed={order === value}
      onClick={() => onChange(value)}
      className={cn(
        "inline-flex h-8 items-center gap-1.5 rounded-md px-3 text-sm font-medium text-muted transition-colors duration-150 [@media(hover:hover)_and_(pointer:fine)]:hover:text-ink",
        order === value && "bg-seg-on font-semibold text-ink shadow-sm",
      )}
    >
      <Icon aria-hidden="true" className="size-4" />
      {label}
    </button>
  )
  return (
    <div role="group" aria-label="Order" className="inline-flex gap-0.5 rounded-lg border border-rule-2 bg-hover p-0.5">
      {choice("latest", "Latest", Clock)}
      {choice("name", "Name", ArrowDownAZ)}
    </div>
  )
}

function Empty() {
  return (
    <>
      <h1 className="text-[28px] font-bold tracking-tight text-ink">No project yet</h1>
      <div className="mt-6 flex items-start gap-3.5 rounded-xl border border-dashed border-rule-2 p-5">
        <span className="grid size-10 flex-none place-items-center rounded-lg bg-hover">
          <FolderGit2 aria-hidden="true" className="size-5 text-ink-2" />
        </span>
        <div>
          <p className="font-semibold text-ink">A project appears here after its first Update</p>
          <p className="mt-0.5 text-sm text-muted">Drop its package.json or requirements.txt in Update.</p>
        </div>
      </div>
      <div className="mt-7 flex justify-end">
        <Button size="page" asChild>
          <Link to="/">
            <RefreshCw aria-hidden="true" />
            Update a project
          </Link>
        </Button>
      </div>
    </>
  )
}

/** Every project with its latest crossing: newest first, or by name under letter headings, once two exist. */
export function ProjectsList({ projects }: { projects: ProjectSummary[] }) {
  const [order, setOrder] = useState<Order>("latest")
  const [all, setAll] = useState(false)

  if (projects.length === 0) {
    return (
      <>
        <EphemeralBanner />
        <div className="animate-enter mx-auto w-full max-w-240 px-5 py-10">
          <Empty />
        </div>
      </>
    )
  }

  const latest = [...projects].sort((a, b) => started(b) - started(a))
  const shown = all ? latest : latest.slice(0, LATEST_ROWS)
  const byLetter = new Map<string, ProjectSummary[]>()
  for (const project of [...projects].sort((a, b) => byName(a.name, b.name))) {
    const letter = nameLetter(project.name)
    byLetter.set(letter, [...(byLetter.get(letter) ?? []), project])
  }

  return (
    <>
      <EphemeralBanner />
      <div className="animate-enter mx-auto w-full max-w-240 px-5 py-10">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <h1 className="text-[28px] font-bold tracking-tight text-ink">
            <span className="figure">{projects.length}</span> {projects.length === 1 ? "project" : "projects"}
          </h1>
          {projects.length >= 2 ? <OrderChoice order={order} onChange={setOrder} /> : null}
        </div>
        <div aria-hidden="true" className={cn("sticky top-[52px] z-10 mt-6 hidden border-b border-rule-2 bg-bg px-3 py-2 text-[13px] font-medium text-muted", COLUMNS)}>
          <span>Project</span>
          <span>Ecosystem</span>
          <span>Latest crossing</span>
          <span>State</span>
        </div>
        {order === "latest" ? (
          <div className="mt-2 md:mt-0">
            <Rows projects={shown} label="Projects" />
            {shown.length < latest.length ? (
              <div className="mt-4">
                <Button variant="outline" onClick={() => setAll(true)}>
                  {`Show all ${latest.length} projects`}
                </Button>
              </div>
            ) : null}
          </div>
        ) : (
          <div aria-label="Projects" role="list" className="mt-2 flex flex-col md:mt-0">
            {[...byLetter].map(([letter, group]) => (
              <section key={letter} role="listitem" aria-labelledby={`letter-${letter}`}>
                <h2 id={`letter-${letter}`} className="border-b border-rule bg-canvas px-3 py-2 text-[13px] font-semibold text-ink-2">
                  {letter}
                </h2>
                <Rows projects={group} />
              </section>
            ))}
          </div>
        )}
      </div>
    </>
  )
}

/** What a Projects page shows while its answer is on the way. */
export function PageReading({ what }: { what: string }) {
  return (
    <div className="mx-auto w-full max-w-240 px-5 py-10">
      <div role="status" className="tinted-info flex w-fit items-center gap-2 px-3 py-2 text-sm text-info">
        <LoaderCircle aria-hidden="true" className="size-4 motion-safe:animate-spin" />
        {`Reading ${what}`}
      </div>
    </div>
  )
}

/** A Projects page whose answer did not come: the cause and Retry, in a closed red row. */
export function PageFailure({ what, error, onRetry }: { what: string; error: Error; onRetry: () => void }) {
  return (
    <div className="mx-auto w-full max-w-240 px-5 py-10">
      <div role="alert" className="tinted-bad flex flex-wrap items-center gap-3 px-4 py-3">
        <CircleX aria-hidden="true" className="size-5 flex-none text-bad" />
        <p className="min-w-0 flex-1 text-sm text-ink [overflow-wrap:anywhere]">
          <span className="font-semibold">{`Could not read ${what}.`}</span> {error.message}
        </p>
        <Button type="button" variant="outline" size="sm" onClick={onRetry}>
          <RotateCw aria-hidden="true" />
          Retry
        </Button>
      </div>
    </div>
  )
}
