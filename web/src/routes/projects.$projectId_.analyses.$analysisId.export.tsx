import { createFileRoute } from "@tanstack/react-router"

export const Route = createFileRoute("/projects/$projectId_/analyses/$analysisId/export")({
  component: ExportPlaceholder,
})

function ExportPlaceholder() {
  return (
    <div className="flex flex-1 items-center justify-center p-8 text-muted">Export is not available yet.</div>
  )
}
