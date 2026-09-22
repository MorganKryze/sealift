import { createRootRoute, Outlet } from "@tanstack/react-router"

import { Nav } from "@/components/nav"

export const Route = createRootRoute({
  component: () => (
    <div className="flex min-h-screen flex-col bg-background text-ink">
      <Nav />
      <main className="flex flex-1 flex-col">
        <Outlet />
      </main>
    </div>
  ),
})
