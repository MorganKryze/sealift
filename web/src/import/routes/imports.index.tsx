import { createFileRoute } from "@tanstack/react-router"

import { ImportsList } from "@/components/import/imports-list"

export const Route = createFileRoute("/imports/")({
  component: () => (
    <>
      <h1 className="text-2xl font-bold tracking-tight">Imports</h1>
      <p className="mt-1.5 text-muted">Every import you started, newest first. Open one to read its report per package.</p>
      <ImportsList />
    </>
  ),
})
