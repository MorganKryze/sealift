import { createFileRoute } from "@tanstack/react-router"

import { OnlineHome } from "@/components/home/online-home"

export const Route = createFileRoute("/")({
  component: OnlineHome,
})
