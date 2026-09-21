import { createFileRoute } from "@tanstack/react-router"

export const Route = createFileRoute("/settings")({
  component: SettingsPlaceholder,
})

function SettingsPlaceholder() {
  return (
    <div className="flex flex-1 items-center justify-center p-8 text-muted">
      Settings are not available yet.
    </div>
  )
}
