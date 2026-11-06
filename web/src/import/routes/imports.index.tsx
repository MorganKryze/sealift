import { createFileRoute } from "@tanstack/react-router"

export const Route = createFileRoute("/imports/")({
  component: () => <h1 className="text-2xl font-bold tracking-tight">Imports</h1>,
})
