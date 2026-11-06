import { createRootRoute, Link, Outlet } from "@tanstack/react-router"

import { ApiFailure } from "@/components/import/api-failure"
import { ImportHeader } from "@/components/import/header"

export const Route = createRootRoute({
  component: () => (
    <div className="flex min-h-screen flex-col bg-background text-ink">
      <ImportHeader />
      <main className="mx-auto flex w-full max-w-240 flex-1 flex-col px-5 py-8">
        <Outlet />
      </main>
    </div>
  ),
  errorComponent: ({ error, reset }) => (
    <div className="mx-auto w-full max-w-240 px-5 py-8">
      <ApiFailure error={error} onRetry={reset} />
    </div>
  ),
  notFoundComponent: () => (
    <div className="mx-auto w-full max-w-240 px-5 py-8">
      <h1 className="text-2xl font-bold tracking-tight">Nothing here</h1>
      <p className="mt-2 text-muted">This address matches no import screen.</p>
      <Link to="/" className="mt-4 inline-flex h-8 items-center text-accent underline">
        Go to archives
      </Link>
    </div>
  ),
})
