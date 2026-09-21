import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { fireEvent, render, screen, waitFor } from "@testing-library/react"
import { beforeEach, describe, expect, it, vi } from "vitest"

import { ProblemError } from "@/api/client"
import { getTools, updateTrivy, type ToolsState } from "@/api/settings"
import { ToolsPanel } from "@/components/settings/tools-panel"

vi.mock("@/api/settings", async () => {
  const actual = await vi.importActual<typeof import("@/api/settings")>("@/api/settings")
  return { ...actual, getTools: vi.fn(), updateTrivy: vi.fn() }
})

const baseTools: ToolsState = {
  pnpmInstalled: ["10.34.5"],
  trivyActive: "0.55.0",
  trivyInstalled: ["0.55.0"],
  trivyLatest: "0.56.0",
  trivyLatestAge: "12h0m0s",
  trivyDbDate: new Date().toISOString(),
}

function renderPanel() {
  const queryClient = new QueryClient()
  render(
    <QueryClientProvider client={queryClient}>
      <ToolsPanel minReleaseAgeDays={3} />
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  vi.mocked(getTools).mockReset().mockResolvedValue(baseTools)
  vi.mocked(updateTrivy).mockReset()
})

describe("ToolsPanel", () => {
  it("shows a 409's detail as a notice on Update Trivy", async () => {
    vi.mocked(updateTrivy).mockRejectedValue(
      new ProblemError(409, {
        type: "about:blank",
        title: "Update in progress",
        status: 409,
        detail: "A tool update is already running.",
      }),
    )

    renderPanel()

    await waitFor(() => screen.getByRole("button", { name: "Update Trivy" }))
    fireEvent.click(screen.getByRole("button", { name: "Update Trivy" }))

    await waitFor(() => {
      expect(screen.getByText("A tool update is already running.")).toBeInTheDocument()
    })
  })
})
