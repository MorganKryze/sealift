import { useQuery, useQueryClient } from "@tanstack/react-query"
import { createFileRoute } from "@tanstack/react-router"

import { getProject, type Export, type Project } from "@/api/projects"
import { ExportDone } from "@/components/projects/export-done"
import { ExportLaunch } from "@/components/projects/export-launch"
import { ExportRunning } from "@/components/projects/export-running"
import { ProjectHeader } from "@/components/projects/project-header"
import { Button } from "@/components/ui/button"
import { latestByDate } from "@/lib/utils"

export const Route = createFileRoute("/projects/$projectId_/analyses/$analysisId/export")({
  component: ExportPage,
})

function ExportPage() {
  const { projectId, analysisId } = Route.useParams()
  const queryClient = useQueryClient()

  const projectQuery = useQuery({
    queryKey: ["project", projectId],
    queryFn: () => getProject(projectId),
    initialData: () => queryClient.getQueryData<Project>(["project", projectId]),
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
        <p role="alert" className="text-sm text-severity-critical">
          Could not load the project
          {projectQuery.error instanceof Error ? `: ${projectQuery.error.message}` : "."}
        </p>
        <Button onClick={() => void projectQuery.refetch()}>Retry</Button>
      </div>
    )
  }

  const project = projectQuery.data
  const analysis = project.analyses?.find((candidate) => candidate.id === analysisId)
  const lastAnalysis = latestByDate(project.analyses)
  const lastExport = latestByDate(project.exports)
  const relatedExport = latestByDate(project.exports?.filter((candidate) => candidate.analysisId === analysisId))

  function onExportChanged() {
    void queryClient.invalidateQueries({ queryKey: ["project", projectId] })
  }

  return (
    <div className="flex flex-1 flex-col">
      <ProjectHeader project={project} lastAnalysis={lastAnalysis} lastExport={lastExport} step={3} />
      {!analysis || analysis.state !== "done" ? (
        <p className="p-8 text-muted">This analysis is not ready for export.</p>
      ) : (
        <ExportSummary
          projectId={projectId}
          analysisId={analysisId}
          analysisCreatedAt={analysis.createdAt}
          relatedExport={relatedExport}
          onChange={onExportChanged}
        />
      )}
    </div>
  )
}

interface ExportSummaryProps {
  projectId: string
  analysisId: string
  analysisCreatedAt: string
  relatedExport?: Export
  onChange: () => void
}

function ExportSummary({ projectId, analysisId, analysisCreatedAt, relatedExport, onChange }: ExportSummaryProps) {
  if (
    !relatedExport ||
    relatedExport.state === "failed" ||
    relatedExport.state === "cancelled" ||
    relatedExport.state === "interrupted"
  ) {
    return (
      <ExportLaunch
        projectId={projectId}
        analysisId={analysisId}
        analysisCreatedAt={analysisCreatedAt}
        previousState={relatedExport?.state}
        onQueued={onChange}
      />
    )
  }

  if (relatedExport.state === "queued" || relatedExport.state === "running") {
    return <ExportRunning projectId={projectId} exportId={relatedExport.id} onEnd={onChange} />
  }

  return <ExportDone projectId={projectId} exportId={relatedExport.id} files={relatedExport.files ?? []} />
}
