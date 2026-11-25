import { createFileRoute } from "@tanstack/react-router"

import { ApiFailure } from "@/components/import/api-failure"
import { OfflineInstancePage } from "@/components/import/instance-page"
import { useMe } from "@/import/api/queries"

export const Route = createFileRoute("/instance")({
  component: InstanceRoute,
})

function InstanceRoute() {
  const me = useMe()
  if (me.isPending) {
    return (
      <div role="status" className="text-muted">
        Loading your instance
      </div>
    )
  }
  if (me.isError) return <ApiFailure error={me.error} onRetry={() => void me.refetch()} />
  return <OfflineInstancePage me={me.data} />
}
