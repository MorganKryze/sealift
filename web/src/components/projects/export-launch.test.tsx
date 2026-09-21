import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { fireEvent, render, screen, waitFor } from "@testing-library/react"
import { beforeEach, describe, expect, it, vi } from "vitest"

import { ProblemError } from "@/api/client"
import { queueExport } from "@/api/projects"
import { ExportLaunch } from "@/components/projects/export-launch"

vi.mock("@/api/projects", async () => {
  const actual = await vi.importActual<typeof import("@/api/projects")>("@/api/projects")
  return { ...actual, queueExport: vi.fn() }
})

function renderLaunch(analysisId: string) {
  const queryClient = new QueryClient()
  render(
    <QueryClientProvider client={queryClient}>
      <ExportLaunch
        projectId="p1"
        analysisId={analysisId}
        analysisCreatedAt={new Date().toISOString()}
        onQueued={() => {}}
      />
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  sessionStorage.clear()
  vi.mocked(queueExport).mockReset()
})

describe("ExportLaunch", () => {
  it("blocks launch when nothing is selected", () => {
    renderLaunch("a-empty")

    expect(screen.getByText("Nothing selected yet.")).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Launch export" })).toBeDisabled()
  })

  it("groups the selection by dependency and enables launch", () => {
    sessionStorage.setItem("sealift:selection:a-grouped", JSON.stringify({ "left-pad": ["1.3.0", "1.4.0"] }))
    renderLaunch("a-grouped")

    expect(screen.getByText("left-pad")).toBeInTheDocument()
    expect(screen.getByText("1.3.0, 1.4.0")).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Launch export" })).not.toBeDisabled()
  })

  it("lists every offending entry on a 400", async () => {
    sessionStorage.setItem("sealift:selection:a-400", JSON.stringify({ "left-pad": ["9.9.9"] }))
    vi.mocked(queueExport).mockRejectedValue(
      new ProblemError(400, {
        type: "about:blank",
        title: "Selection invalid",
        status: 400,
        errors: [
          { field: "selection", name: "left-pad", value: "9.9.9", reason: "not a resolved candidate" },
          { field: "selection", name: "chalk", value: "1.0.0", reason: "not a resolved candidate" },
        ],
      }),
    )

    renderLaunch("a-400")
    fireEvent.click(screen.getByRole("button", { name: "Launch export" }))

    await waitFor(() => {
      expect(screen.getAllByText(/not a resolved candidate/).length).toBe(2)
    })
  })
})
