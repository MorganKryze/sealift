import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { fireEvent, render, screen, waitFor } from "@testing-library/react"
import { beforeEach, describe, expect, it, vi } from "vitest"

import { ProblemError } from "@/api/client"
import { getTools, updateTrivy, updateTrivyDB, type ToolsState } from "@/api/settings"
import { ToolsPanel } from "@/components/settings/tools-panel"

vi.mock("@/api/settings", async () => {
  const actual = await vi.importActual<typeof import("@/api/settings")>("@/api/settings")
  return { ...actual, getTools: vi.fn(), updateTrivy: vi.fn(), updateTrivyDB: vi.fn() }
})

const baseTools: ToolsState = {
  pnpmInstalled: ["10.34.5"],
  trivyActive: "0.55.0",
  trivyInstalled: ["0.55.0"],
  trivyLatest: "0.56.0",
  trivyLatestAge: "12h0m0s",
  trivyDbDate: new Date().toISOString(),
  latestSizeBytes: 83886080,
  ready: true,
  missing: [],
}

function renderPanel() {
  const queryClient = new QueryClient()
  render(
    <QueryClientProvider client={queryClient}>
      <ToolsPanel minReleaseAgeDays={3} pnpmVersion="10.34.5" />
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  vi.mocked(getTools).mockReset().mockResolvedValue(baseTools)
  vi.mocked(updateTrivy).mockReset()
  vi.mocked(updateTrivyDB).mockReset()
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

  it("shows the update running, then says Trivy was already current", async () => {
    let finish: (state: ToolsState) => void = () => {}
    vi.mocked(updateTrivy).mockReturnValue(new Promise((resolve) => (finish = resolve)))

    renderPanel()
    await waitFor(() => screen.getByRole("button", { name: "Update Trivy" }))
    fireEvent.click(screen.getByRole("button", { name: "Update Trivy" }))

    await waitFor(() => expect(screen.getByRole("button", { name: /Checking for a newer Trivy/ })).toBeDisabled())
    finish(baseTools)
    await waitFor(() => expect(screen.getByText("Trivy 0.55.0 is already the newest release sealift installs.")).toBeInTheDocument())
  })

  it("says which Trivy it installed", async () => {
    vi.mocked(updateTrivy).mockResolvedValue({ ...baseTools, trivyActive: "0.56.0", trivyInstalled: ["0.55.0", "0.56.0"] })

    renderPanel()
    await waitFor(() => screen.getByRole("button", { name: "Update Trivy" }))
    fireEvent.click(screen.getByRole("button", { name: "Update Trivy" }))

    await waitFor(() => expect(screen.getByText("Trivy 0.56.0 installed and active.")).toBeInTheDocument())
  })

  it("shows the database update running, then its new date", async () => {
    let finish: (state: ToolsState) => void = () => {}
    vi.mocked(updateTrivyDB).mockReturnValue(new Promise((resolve) => (finish = resolve)))

    renderPanel()
    await waitFor(() => screen.getByRole("button", { name: "Update database" }))
    fireEvent.click(screen.getByRole("button", { name: "Update database" }))

    await waitFor(() => expect(screen.getByRole("button", { name: /Updating the database/ })).toBeDisabled())
    finish({ ...baseTools, trivyDbDate: new Date(Date.parse(baseTools.trivyDbDate) + 3600_000).toISOString() })
    await waitFor(() => expect(screen.getByText(/^Database updated/)).toBeInTheDocument())
  })

  it("says the database was already current when its date did not move", async () => {
    vi.mocked(updateTrivyDB).mockResolvedValue(baseTools)

    renderPanel()
    await waitFor(() => screen.getByRole("button", { name: "Update database" }))
    fireEvent.click(screen.getByRole("button", { name: "Update database" }))

    await waitFor(() => expect(screen.getByText(/^The database is already current/)).toBeInTheDocument())
  })
})
