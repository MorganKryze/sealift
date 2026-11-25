import { createFileRoute } from "@tanstack/react-router"

import { UpdateScreen } from "@/components/session/update-screen"

export const Route = createFileRoute("/update")({
  component: UpdateScreen,
})
