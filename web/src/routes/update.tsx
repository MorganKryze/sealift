import { createFileRoute } from "@tanstack/react-router"

import { UpdateScreen } from "@/components/session/update-screen"

// `from` names the pip project a new crossing continues; any other search is dropped.
export const Route = createFileRoute("/update")({
  validateSearch: (search: Record<string, unknown>): { from?: string } => (typeof search.from === "string" && search.from.trim() !== "" ? { from: search.from } : {}),
  component: UpdateRoute,
})

function UpdateRoute() {
  const { from } = Route.useSearch()
  return <UpdateScreen from={from} />
}
