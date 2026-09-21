import type { ReactNode } from "react"

import type { ProjectSummary } from "@/api/projects"
import { EmptyState } from "@/components/empty-state"
import { DropZone } from "@/components/projects/drop-zone"
import { ProjectsTable } from "@/components/projects/projects-table"
import { Button } from "@/components/ui/button"

interface ProjectsViewProps {
  status: "pending" | "error" | "success"
  projects?: ProjectSummary[]
  error?: Error | null
  onRetry: () => void
  onFile: (file: File) => void
  onInvalidFile: (message: string) => void
  children?: ReactNode
}

/**
 * Renders the /projects route for each query status. Kept apart from the
 * route file so the loading and error states can be tested without a router
 * or react-query context.
 */
export function ProjectsView({
  status,
  projects,
  error,
  onRetry,
  onFile,
  onInvalidFile,
  children,
}: ProjectsViewProps) {
  if (status === "pending") {
    return (
      <div role="status" className="flex flex-1 items-center justify-center p-8 text-muted">
        Loading projects…
      </div>
    )
  }

  if (status === "error") {
    return (
      <div className="flex flex-1 flex-col items-center justify-center gap-3 p-8 text-center">
        <p role="alert" className="text-sm text-severity-critical">
          Could not load projects{error?.message ? `: ${error.message}` : "."}
        </p>
        <Button onClick={onRetry}>Retry</Button>
      </div>
    )
  }

  const list = projects ?? []

  if (list.length === 0) {
    return (
      <EmptyState onFile={onFile} onInvalidFile={onInvalidFile}>
        {children}
      </EmptyState>
    )
  }

  return (
    <div className="flex flex-1 flex-col gap-6 p-8">
      <h1 className="text-xl font-semibold text-ink">Projects</h1>
      {children}
      <ProjectsTable projects={list} />
      <DropZone onFile={onFile} onInvalidFile={onInvalidFile} compact />
    </div>
  )
}
