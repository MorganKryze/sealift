import { useQueries, useQuery } from "@tanstack/react-query"
import { CircleDashed, CircleX, Clock, ListChecks, LoaderCircle, Lock, RefreshCw, RotateCw } from "lucide-react"
import { useState } from "react"

import { getProject, listProjects, type ProjectSummary } from "@/api/projects"
import { EmptyGroup, type HomeRow, PathCard, RowGroup, type Tone } from "@/components/home/blocks"
import { Button } from "@/components/ui/button"
import { crossingName, crossingState } from "@/lib/crossings"

// A group shows this many rows before its Show all; the home reads the history of those rows only.
const GROUP_ROWS = 10
// While a crossing runs, the home asks again so a finished or failed one leaves In progress.
const POLL_MS = 5000

type Group = "needs" | "progress"

interface Placed {
  project: ProjectSummary
  group: Group
  row: Omit<HomeRow, "name">
}

/** Where a project's latest crossing belongs on the home, or nowhere once it is sealed or cancelled. */
function place(project: ProjectSummary): Placed | null {
  const last = project.lastAnalysis
  // An export counts only when it belongs to the latest analysis.
  const exported = last && project.lastExport?.analysisId === last.id ? project.lastExport : undefined
  const state = crossingState(last, exported)
  const session = `/sessions/${encodeURIComponent(project.id)}`
  const row = (icon: HomeRow["icon"], tone: Tone, action: HomeRow["action"]) => ({
    key: project.id,
    icon,
    detail: "Update",
    state: { label: state.label, tone },
    action,
  })
  switch (state.kind) {
    case "waits":
      return { project, group: "needs", row: row(ListChecks, "warn", { label: "Review", to: `${session}/review` }) }
    case "failed":
      return { project, group: "needs", row: row(CircleX, "bad", { label: "Open", to: session }) }
    case "new":
      return { project, group: "needs", row: row(CircleDashed, "warn", { label: "Open", to: `${session}/drop` }) }
    case "queued":
      return { project, group: "progress", row: row(Clock, "info", { label: "Open", to: session }) }
    case "running":
      return { project, group: "progress", row: row(exported ? Lock : LoaderCircle, "info", { label: "Open", to: session }) }
    case "sealed":
    case "cancelled":
      return null
  }
}

// A project never analysed has no date; it files after every crossing.
const started = ({ project }: Placed) => (project.lastAnalysis ? new Date(project.lastAnalysis.createdAt).getTime() : -Infinity)

/** The Online home: start a crossing, then what needs the developer, then what runs without them. */
export function OnlineHome() {
  const projects = useQuery({
    queryKey: ["projects"],
    queryFn: () => listProjects(),
    refetchInterval: (query) => (query.state.data?.some((project) => place(project)?.group === "progress") ? POLL_MS : false),
  })
  const [expanded, setExpanded] = useState<Record<Group, boolean>>({ needs: false, progress: false })

  const placed = (projects.data ?? []).map(place).filter((entry): entry is Placed => entry !== null)
  placed.sort((a, b) => started(b) - started(a))
  const groups: Record<Group, Placed[]> = {
    needs: placed.filter((entry) => entry.group === "needs"),
    progress: placed.filter((entry) => entry.group === "progress"),
  }
  const shown = (Object.keys(groups) as Group[]).flatMap((group) => (expanded[group] ? groups[group] : groups[group].slice(0, GROUP_ROWS)))
  // A crossing's " · 2" needs the project's other analyses of that day, which the list does not carry.
  const histories = useQueries({
    queries: shown
      .filter(({ project }) => project.lastAnalysis)
      .map(({ project }) => ({ queryKey: ["project", project.id], queryFn: () => getProject(project.id) })),
  })
  const analysesOf = new Map(histories.flatMap((query) => (query.data ? [[query.data.id, query.data.analyses ?? []] as const] : [])))

  const rows = (group: Group): HomeRow[] =>
    groups[group].map(({ project, row }) => {
      const last = project.lastAnalysis
      const name = last ? crossingName(project.name, last, analysesOf.get(project.id) ?? [last]) : project.name
      return { ...row, name }
    })

  const holdsNoCrossing = projects.isSuccess && projects.data.every((project) => !project.lastAnalysis)

  return (
    <div className="animate-enter mx-auto w-full max-w-170 px-5 py-10">
      <h1 className="text-[28px] font-bold tracking-tight text-ink">Start a crossing</h1>
      <div className="mt-6">
        <PathCard to="/update" icon={RefreshCw} title="Update" detail="a project" lead />
      </div>

      {projects.isPending ? (
        <div role="status" className="tinted-info mt-10 flex w-fit items-center gap-2 px-3 py-2 text-sm text-info">
          <LoaderCircle aria-hidden="true" className="size-4 motion-safe:animate-spin" />
          Reading crossings
        </div>
      ) : projects.isError ? (
        <div role="alert" className="tinted-bad mt-10 flex flex-wrap items-center gap-3 px-4 py-3">
          <CircleX aria-hidden="true" className="size-5 flex-none text-bad" />
          <p className="min-w-0 flex-1 text-sm text-ink [overflow-wrap:anywhere]">
            <span className="font-semibold">Could not read the crossings.</span> {projects.error.message}
          </p>
          <Button type="button" variant="outline" size="sm" onClick={() => void projects.refetch()}>
            <RotateCw aria-hidden="true" />
            Retry
          </Button>
        </div>
      ) : (
        <>
          <RowGroup title="Needs you" rows={rows("needs")} noun={["crossing", "crossings"]} onShowAll={() => setExpanded((e) => ({ ...e, needs: true }))} />
          {holdsNoCrossing ? (
            <EmptyGroup title="In progress" text="No crossing in progress" />
          ) : (
            <RowGroup title="In progress" rows={rows("progress")} noun={["crossing", "crossings"]} onShowAll={() => setExpanded((e) => ({ ...e, progress: true }))} />
          )}
        </>
      )}
    </div>
  )
}
