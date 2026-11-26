import { Link } from "@tanstack/react-router"
import { ChevronDown, ChevronRight } from "lucide-react"
import { useState } from "react"

import type { Analysis, Export, Project } from "@/api/projects"
import { CrossingFiles } from "@/components/projects/crossing-files"
import { StateChip, StateIcon } from "@/components/projects/projects-list"
import { crossingName, crossingState } from "@/lib/crossings"
import { cn, latestByDate } from "@/lib/utils"

const newestFirst = (a: { createdAt: string }, b: { createdAt: string }) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()

function TargetLine({ project }: { project: Project }) {
  if (project.ecosystem === "pip" && project.pipTarget) {
    const t = project.pipTarget
    return (
      <p className="mt-1 text-muted">
        pip · Python <span className="figure text-ink-2">{t.python}</span> · {t.os} {t.cpu} · glibc <span className="figure text-ink-2">{t.glibc}</span>
      </p>
    )
  }
  if (project.target) {
    const t = project.target
    return (
      <p className="mt-1 text-muted">
        {project.ecosystem} · Node <span className="figure text-ink-2">{t.node}</span> · {t.os} {t.cpu}
      </p>
    )
  }
  return <p className="mt-1 text-muted">{project.ecosystem}</p>
}

/** A project and its crossings, newest first; a sealed crossing opens its files in place. */
export function ProjectPage({ project }: { project: Project }) {
  const analyses = [...(project.analyses ?? [])].sort(newestFirst)
  const exportsOf = (analysis: Analysis) => (project.exports ?? []).filter((e) => e.analysisId === analysis.id)
  const sealedOf = (analysis: Analysis) => latestByDate(exportsOf(analysis).filter((e) => e.state === "done"))
  const [open, setOpen] = useState<string | undefined>(() => analyses.find((a) => sealedOf(a))?.id)

  return (
    <div className="animate-enter mx-auto w-full max-w-240 px-5 py-10">
      <h1 className="text-[28px] font-bold tracking-tight text-ink [overflow-wrap:anywhere]">{project.name}</h1>
      <TargetLine project={project} />
      <h2 className="mt-8 text-lg font-semibold text-ink">
        {analyses.length === 0 ? (
          "No crossing yet"
        ) : (
          <>
            <span className="figure">{analyses.length}</span> {analyses.length === 1 ? "crossing" : "crossings"}
          </>
        )}
      </h2>
      {analyses.length > 0 ? (
        <ol aria-label="Crossings" className="mt-3 overflow-hidden rounded-xl border border-rule">
          {analyses.map((analysis) => (
            <Crossing
              key={analysis.id}
              project={project}
              analysis={analysis}
              name={crossingName(project.name, analysis, analyses)}
              exported={latestByDate(exportsOf(analysis))}
              sealed={sealedOf(analysis)}
              open={open === analysis.id}
              onToggle={() => setOpen((current) => (current === analysis.id ? undefined : analysis.id))}
            />
          ))}
        </ol>
      ) : null}
    </div>
  )
}

interface CrossingProps {
  project: Project
  analysis: Analysis
  name: string
  exported?: Export
  sealed?: Export
  open: boolean
  onToggle: () => void
}

function Crossing({ project, analysis, name, exported, sealed, open, onToggle }: CrossingProps) {
  const state = crossingState(analysis, exported)
  const prefix = `${project.name} · `
  const files = sealed?.files ?? []
  return (
    <li className="border-b border-rule last:border-b-0">
      <div
        className={cn(
          "flex items-center gap-3 px-4 py-3",
          state.kind === "failed" && "tinted-bad m-1.5 px-2.5 py-2",
          state.kind === "cancelled" && "bg-hover",
          open && "bg-canvas",
        )}
      >
        <StateIcon kind={state.kind} />
        <div className="min-w-0 flex-1">
          <h3 className="text-[15px] text-ink [overflow-wrap:anywhere]">
            <span className="text-muted">{`${project.name} ·`}</span>{" "}
            <span className="figure">{name.slice(prefix.length)}</span>
          </h3>
          <p className="mt-0.5 flex flex-wrap items-center gap-2 text-sm text-muted">
            Update <StateChip {...state} />
          </p>
        </div>
        {sealed && files.length > 0 ? (
          <button
            type="button"
            aria-expanded={open}
            onClick={onToggle}
            className="inline-flex h-8 items-center gap-1.5 rounded-md px-2 text-sm text-ink transition-colors duration-150 [@media(hover:hover)_and_(pointer:fine)]:hover:bg-hover"
          >
            <span className="figure">{files.length}</span> files
            <ChevronDown aria-hidden="true" className={cn("size-4 text-muted", open && "rotate-180")} />
          </button>
        ) : null}
        <Link
          to="/sessions/$sessionId/analysis"
          params={{ sessionId: project.id }}
          search={{ analysis: analysis.id }}
          aria-label={`Open ${name}`}
          className="grid size-8 flex-none place-items-center rounded-md text-faint transition-colors duration-150 [@media(hover:hover)_and_(pointer:fine)]:hover:bg-hover [@media(hover:hover)_and_(pointer:fine)]:hover:text-ink"
        >
          <ChevronRight aria-hidden="true" className="size-4" />
        </Link>
      </div>
      {open && sealed ? <CrossingFiles project={project} exported={sealed} /> : null}
    </li>
  )
}
