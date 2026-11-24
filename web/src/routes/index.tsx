import { createFileRoute } from "@tanstack/react-router"

import { HomeScreen } from "@/components/session/home-screen"
import { WhenReady } from "@/components/preparing-screen"

export const Route = createFileRoute("/")({
  component: IndexRoute,
})

function IndexRoute() {
  return (
    <WhenReady>
      <HomeScreen />
    </WhenReady>
  )
}
