import { createFileRoute, Navigate } from "@tanstack/react-router"
import { useEffect } from "react"

import { useSettingsPanel } from "@/components/settings/settings-panel"

export const Route = createFileRoute("/settings")({
  component: SettingsAddress,
})

/** Settings live in a side panel; this address opens it over the home screen. */
function SettingsAddress() {
  const settingsPanel = useSettingsPanel()
  useEffect(() => settingsPanel.open(), [settingsPanel])
  return <Navigate to="/" replace />
}
