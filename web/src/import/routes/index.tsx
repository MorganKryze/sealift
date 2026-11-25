import { createFileRoute } from "@tanstack/react-router"

import { OfflineHome } from "@/components/import/offline-home"

export const Route = createFileRoute("/")({
  component: OfflineHome,
})
