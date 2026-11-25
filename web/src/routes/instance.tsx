import { createFileRoute } from "@tanstack/react-router"

import { useInstance } from "@/components/preparing-screen"
import { InstancePage } from "@/components/settings/instance-page"

export const Route = createFileRoute("/instance")({
  component: InstanceRoute,
})

// The root draws its pages only once the instance answered ready, so the answer is in the cache here.
function InstanceRoute() {
  const instance = useInstance()
  return instance.data ? <InstancePage instance={instance.data} /> : null
}
