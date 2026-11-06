import { createFileRoute } from "@tanstack/react-router"

export const Route = createFileRoute("/imports/$importId")({
  component: ImportRoute,
})

function ImportRoute() {
  const { importId } = Route.useParams()
  return (
    <>
      <h1 className="text-2xl font-bold tracking-tight">Import</h1>
      <p className="mt-2 font-mono text-sm text-muted [overflow-wrap:anywhere]">{importId}</p>
    </>
  )
}
