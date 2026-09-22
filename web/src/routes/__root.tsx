import { createRootRoute, Outlet } from "@tanstack/react-router"

import { Nav } from "@/components/nav"
import { SettingsPanelProvider } from "@/components/settings/settings-panel"

export const Route = createRootRoute({
  component: () => (
    <SettingsPanelProvider>
      <div className="flex min-h-screen flex-col bg-background text-ink">
        <Nav />
        <main className="flex flex-1 flex-col">
          <Outlet />
        </main>
      </div>
    </SettingsPanelProvider>
  ),
})
