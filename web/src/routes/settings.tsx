import { useQuery } from "@tanstack/react-query"
import { createFileRoute } from "@tanstack/react-router"

import { getSettings } from "@/api/settings"
import { SettingsForm } from "@/components/settings/settings-form"
import { ToolsPanel } from "@/components/settings/tools-panel"

export const Route = createFileRoute("/settings")({
  component: SettingsScreen,
})

function SettingsScreen() {
  const settingsQuery = useQuery({ queryKey: ["settings"], queryFn: getSettings })

  return (
    <div className="flex flex-1 flex-col gap-8 p-8">
      <h1 className="text-xl font-semibold text-ink">Settings</h1>

      {settingsQuery.isPending ? (
        <p role="status" className="text-muted">
          Loading settings…
        </p>
      ) : settingsQuery.isError ? (
        <p role="alert" className="text-sm text-severity-critical-fg">
          Could not load settings.
        </p>
      ) : (
        <>
          <SettingsForm settings={settingsQuery.data} />
          <ToolsPanel minReleaseAgeDays={settingsQuery.data.minReleaseAgeDays} />
        </>
      )}
    </div>
  )
}
