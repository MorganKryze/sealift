import { useQuery } from "@tanstack/react-query"
import { createRootRoute, Outlet, redirect, useRouterState } from "@tanstack/react-router"

import { getProject } from "@/api/projects"
import { Frame } from "@/components/frame/frame"
import { useInstance, WhenReady } from "@/components/preparing-screen"
import { ONLINE_INSTANCE, ONLINE_PLACES, onlineCrumbs } from "@/lib/places"
import { analysisSearch } from "@/lib/session-analysis"

export const Route = createRootRoute({
  // The settings sheet's old address, kept so a bookmark lands on Instance.
  beforeLoad: ({ location }) => {
    if (location.pathname === "/settings") throw redirect({ to: "/instance", replace: true })
    // The session pages' old addresses, kept so a bookmark lands on its crossing, at the step it named.
    const earlier = /^\/sessions\/([^/]+)(?:\/(drop|analysis|review|export))?\/?$/.exec(location.pathname)
    if (earlier) {
      const step = earlier[2] === "drop" ? "check" : earlier[2] === "review" ? "review" : undefined
      throw redirect({
        to: "/crossings/$projectId",
        params: { projectId: decoded(earlier[1]) },
        search: { ...analysisSearch(location.search), ...(step ? { step } : {}) },
        replace: true,
      })
    }
  },
  component: () => (
    <WhenReady>
      <OnlineFrame />
    </WhenReady>
  ),
})

/** A path segment as the router's params hold it; a malformed escape stays as written. */
function decoded(segment: string): string {
  try {
    return decodeURIComponent(segment)
  } catch {
    return segment
  }
}

function OnlineFrame() {
  const instance = useInstance()
  const pathname = useRouterState({ select: (s) => s.location.pathname })
  const analysisId = useRouterState({ select: (s) => analysisSearch(s.location.search).analysis })
  const projectId = /^\/(?:crossings|projects)\/([^/]+)/.exec(pathname)?.[1]
  // The page's own route asks for the same cache entry, so the crumb costs no extra request.
  const project = useQuery({
    queryKey: ["project", projectId],
    queryFn: () => getProject(projectId ?? ""),
    enabled: projectId !== undefined,
  })

  return (
    <Frame side="online" places={ONLINE_PLACES} instance={ONLINE_INSTANCE} instanceWarning={instance.data?.warning} crumbs={onlineCrumbs(pathname, projectId ? project.data : undefined, analysisId)}>
      <Outlet />
    </Frame>
  )
}
