import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { fireEvent, render, screen, waitFor } from "@testing-library/react"
import { beforeEach, describe, expect, it, vi } from "vitest"

import { ApiError } from "@/api/client"
import { queueAnalysis, type Analysis } from "@/api/projects"
import { AnalysisFailed } from "@/components/projects/analysis-failed"

vi.mock("@/api/projects", async () => {
  const actual = await vi.importActual<typeof import("@/api/projects")>("@/api/projects")
  return { ...actual, queueAnalysis: vi.fn() }
})

const baseAnalysis: Analysis = {
  id: "a1",
  projectId: "p1",
  state: "failed",
  createdAt: "2026-09-01T00:00:00Z",
}

function renderFailed(analysis: Analysis) {
  const queryClient = new QueryClient()
  render(
    <QueryClientProvider client={queryClient}>
      <AnalysisFailed projectId="p1" analysis={analysis} />
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  vi.mocked(queueAnalysis).mockReset()
})

describe("AnalysisFailed", () => {
  it("names the failed step when status.json recorded one", () => {
    renderFailed({ ...baseAnalysis, failedStep: "scan" })

    expect(screen.getByText(/Stopped at scan\./)).toBeInTheDocument()
  })

  it("shows the problem's title and detail when the rerun fails", async () => {
    vi.mocked(queueAnalysis).mockRejectedValue(
      new ApiError(500, { type: "about:blank", title: "queue analysis", status: 500, detail: "queue is closed" }),
    )
    renderFailed(baseAnalysis)

    fireEvent.click(screen.getByRole("button", { name: "Rerun analysis" }))

    await waitFor(() => {
      expect(screen.getByText("queue analysis")).toBeInTheDocument()
    })
    expect(screen.getByText("queue is closed")).toBeInTheDocument()
  })
})
