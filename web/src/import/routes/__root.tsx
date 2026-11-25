import { createRootRoute, Link, Outlet, useRouterState } from "@tanstack/react-router"
import type { ReactNode } from "react"

import { BrandProvider, DEFAULT_BRAND } from "@/components/frame/brand"
import { Frame } from "@/components/frame/frame"
import { ApiFailure } from "@/components/import/api-failure"
import { useMe } from "@/import/api/queries"
import { OFFLINE_INSTANCE, OFFLINE_PLACES, offlineCrumbs } from "@/import/lib/places"

export const Route = createRootRoute({
  component: () => (
    <OfflineFrame>
      <Outlet />
    </OfflineFrame>
  ),
  errorComponent: ({ error, reset }) => (
    <OfflineFrame>
      <ApiFailure error={error} onRetry={reset} />
    </OfflineFrame>
  ),
  notFoundComponent: () => (
    <>
      <h1 className="text-2xl font-bold tracking-tight">Nothing here</h1>
      <p className="mt-2 text-muted">This address matches no import screen.</p>
      <Link to="/" className="mt-4 inline-flex h-8 items-center self-start text-ink underline">
        Go to Home
      </Link>
    </>
  ),
})

// The import side serves no brand yet, so it shows the defaults.
function OfflineFrame({ children }: { children: ReactNode }) {
  const pathname = useRouterState({ select: (s) => s.location.pathname })
  const me = useMe()
  return (
    <BrandProvider brand={DEFAULT_BRAND}>
      <Frame side="offline" places={OFFLINE_PLACES} instance={OFFLINE_INSTANCE} user={me.data?.user} crumbs={offlineCrumbs(pathname)}>
        <div className="mx-auto flex w-full max-w-240 flex-1 flex-col px-5 py-8">{children}</div>
      </Frame>
    </BrandProvider>
  )
}
