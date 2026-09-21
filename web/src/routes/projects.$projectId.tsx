import { useQuery, useQueryClient } from "@tanstack/react-query"
import { createFileRoute, useNavigate } from "@tanstack/react-router"
import { useState } from "react"

import { getProject, type Analysis, type Project } from "@/api/projects"
import { AnalysisFailed } from "@/components/projects/analysis-failed"
import { AnalysisResults } from "@/components/projects/analysis-results"
import { AnalysisRunning } from "@/components/projects/analysis-running"
import { ProjectHeader } from "@/components/projects/project-header"
import { ProjectHistory } from "@/components/projects/project-history"
import { Button } from "@/components/ui/button"
import { cn, isJobActive, JOB_POLL_INTERVAL_MS, latestByDate } from "@/lib/utils"

export const Route = createFileRoute("/projects/$projectId")({
  component: ProjectPage,
})

type Tab = "results" | "history"

const TABS: Tab[] = ["results", "history"]

function ProjectPage() {
  const { projectId } = Route.useParams()
  const queryClient = useQueryClient()
  const [tab, setTab] = useState<Tab>("results")

  const projectQuery = useQuery({
    queryKey: ["project", projectId],
    queryFn: () => getProject(projectId),
    initialData: () => queryClient.getQueryData<Project>(["project", projectId]),
    refetchInterval: (query) => {
      const project = query.state.data
      const active = isJobActive(latestByDate(project?.analyses)) || isJobActive(latestByDate(project?.exports))
      return active ? JOB_POLL_INTERVAL_MS : false
    },
  })

  if (projectQuery.isPending) {
    return (
      <div role="status" className="flex flex-1 items-center justify-center p-8 text-muted">
        Loading project…
      </div>
    )
  }

  if (projectQuery.isError) {
    return (
      <div className="flex flex-1 flex-col items-center justify-center gap-3 p-8 text-center">
        <p role="alert" className="text-sm text-severity-critical-fg">
          Could not load the project
          {projectQuery.error instanceof Error ? `: ${projectQuery.error.message}` : "."}
        </p>
        <Button onClick={() => void projectQuery.refetch()}>Retry</Button>
      </div>
    )
  }

  const project = projectQuery.data
  const lastAnalysis = latestByDate(project.analyses)
  const lastExport = latestByDate(project.exports)

  return (
    <div className="flex flex-1 flex-col">
      <ProjectHeader project={project} lastAnalysis={lastAnalysis} lastExport={lastExport} />
      <div role="tablist" className="flex gap-1 border-b border-line px-8 pt-4">
        {TABS.map((value) => (
          <button
            key={value}
            role="tab"
            aria-selected={tab === value}
            onClick={() => setTab(value)}
            className={cn(
              "rounded-t-md px-4 py-2 text-sm font-medium capitalize outline-none focus-visible:ring-2 focus-visible:ring-accent",
              tab === value ? "border-b-2 border-accent text-ink" : "text-muted hover:text-ink",
            )}
          >
            {value}
          </button>
        ))}
      </div>
      <div className="flex flex-1 flex-col">
        {tab === "results" ? (
          <AnalysisSummary projectId={projectId} analysis={lastAnalysis} />
        ) : (
          <ProjectHistory analyses={project.analyses ?? []} exports={project.exports ?? []} />
        )}
      </div>
    </div>
  )
}

function AnalysisSummary({ projectId, analysis }: { projectId: string; analysis?: Analysis }) {
  const navigate = useNavigate()

  if (!analysis) {
    return <p className="p-8 text-muted">No analysis yet.</p>
  }

  function onContinue() {
    void navigate({
      to: "/projects/$projectId/analyses/$analysisId/export",
      params: { projectId, analysisId: analysis!.id },
    })
  }

  if (analysis.state === "queued" || analysis.state === "running") {
    return <AnalysisRunning projectId={projectId} analysisId={analysis.id} />
  }

  if (analysis.state === "failed" || analysis.state === "cancelled" || analysis.state === "interrupted") {
    return <AnalysisFailed projectId={projectId} analysis={analysis} />
  }

  if (analysis.state === "done" && analysis.result) {
    return (
      <AnalysisResults
        analysisId={analysis.id}
        result={analysis.result}
        trivyVersion={analysis.trivyVersion}
        trivyDbDate={analysis.trivyDbDate}
        pnpmVersion={analysis.pnpmVersion}
        onContinue={onContinue}
      />
    )
  }

  return <p className="p-8 text-muted">Analysis {analysis.state}.</p>
}
