import { useQuery } from "@tanstack/react-query"
import { createFileRoute } from "@tanstack/react-router"

import { getTools } from "@/api/settings"
import { HomeScreen } from "@/components/session/home-screen"
import { SetupScreen } from "@/components/setup-screen"
import { Button } from "@/components/ui/button"

export const Route = createFileRoute("/")({
  component: IndexRoute,
})

function IndexRoute() {
  const toolsQuery = useQuery({ queryKey: ["tools"], queryFn: getTools })

  if (toolsQuery.isPending) {
    return (
      <div role="status" className="flex flex-1 items-center justify-center p-8 text-muted">
        Loading…
      </div>
    )
  }

  if (toolsQuery.isError) {
    return (
      <div className="flex flex-1 flex-col items-center justify-center gap-3 p-8 text-center">
        <p role="alert" className="text-sm text-severity-critical-fg">
          Could not reach sealift.
        </p>
        <Button onClick={() => void toolsQuery.refetch()}>Retry</Button>
      </div>
    )
  }

  if (!toolsQuery.data.ready) {
    return <SetupScreen tools={toolsQuery.data} />
  }

  return <HomeScreen />
}
