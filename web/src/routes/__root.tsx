import { useQuery } from "@tanstack/react-query"
import { createRootRoute, Outlet, useRouterState } from "@tanstack/react-router"

import { getProject } from "@/api/projects"
import { EphemeralBanner } from "@/components/ephemeral"
import { Frame } from "@/components/frame/frame"
import { useInstance, WhenReady } from "@/components/preparing-screen"
import { SettingsPanelProvider } from "@/components/settings/settings-panel"
import { ONLINE_INSTANCE, ONLINE_PLACES, onlineCrumbs } from "@/lib/places"

export const Route = createRootRoute({
  component: () => (
    <WhenReady>
      <SettingsPanelProvider>
        <OnlineFrame />
      </SettingsPanelProvider>
    </WhenReady>
  ),
})

function OnlineFrame() {
  const instance = useInstance()
  const pathname = useRouterState({ select: (s) => s.location.pathname })
  const projectId = /^\/(?:sessions|projects)\/([^/]+)/.exec(pathname)?.[1]
  // The page's own route asks for the same cache entry, so the crumb costs no extra request.
  const project = useQuery({
    queryKey: ["project", projectId],
    queryFn: () => getProject(projectId ?? ""),
    enabled: projectId !== undefined,
  })

  return (
    <Frame side="online" places={ONLINE_PLACES} instance={ONLINE_INSTANCE} instanceWarning={instance.data?.warning} crumbs={onlineCrumbs(pathname, projectId ? project.data : undefined)}>
      <EphemeralBanner />
      <Outlet />
    </Frame>
  )
}
