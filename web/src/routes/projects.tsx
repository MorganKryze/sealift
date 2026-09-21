import { createFileRoute } from "@tanstack/react-router"

import { EmptyState } from "@/components/empty-state"

export const Route = createFileRoute("/projects")({
  component: EmptyState,
})
