import { fireEvent, render, screen, waitFor } from "@testing-library/react"
import { beforeEach, describe, expect, it, vi } from "vitest"

import { ApiError } from "@/api/client"
import { cancelExport } from "@/api/projects"
import { ExportRunning } from "@/components/projects/export-running"
import { initialAnalysisEventsState, type AnalysisEventsState } from "@/lib/analysisEvents"

vi.mock("@/api/projects", async () => {
  const actual = await vi.importActual<typeof import("@/api/projects")>("@/api/projects")
  return { ...actual, cancelExport: vi.fn() }
})

let mockEventsState: AnalysisEventsState = initialAnalysisEventsState

vi.mock("@/hooks/use-job-events", () => ({
  useJobEvents: () => mockEventsState,
}))

beforeEach(() => {
  mockEventsState = initialAnalysisEventsState
  vi.mocked(cancelExport).mockReset()
  vi.mocked(cancelExport).mockResolvedValue({} as never)
  vi.spyOn(window, "confirm").mockReturnValue(true)
})

describe("ExportRunning", () => {
  it("asks for confirmation before cancelling and calls the cancel route", async () => {
    mockEventsState = { ...initialAnalysisEventsState, progress: { done: 1, total: 4 } }
    render(<ExportRunning projectId="p1" exportId="e1" onEnd={() => {}} />)

    fireEvent.click(screen.getByRole("button", { name: "Cancel" }))

    expect(window.confirm).toHaveBeenCalledWith("Cancel this export?")
    await waitFor(() => {
      expect(cancelExport).toHaveBeenCalledWith("p1", "e1")
    })
  })

  it("does not cancel when the confirmation is declined", () => {
    vi.mocked(window.confirm).mockReturnValue(false)
    mockEventsState = { ...initialAnalysisEventsState, progress: { done: 1, total: 4 } }
    render(<ExportRunning projectId="p1" exportId="e1" onEnd={() => {}} />)

    fireEvent.click(screen.getByRole("button", { name: "Cancel" }))

    expect(cancelExport).not.toHaveBeenCalled()
  })

  it("shows the cache hit count when present", () => {
    mockEventsState = { ...initialAnalysisEventsState, progress: { done: 2, total: 4, cacheHits: 2 } }
    render(<ExportRunning projectId="p1" exportId="e1" onEnd={() => {}} />)

    expect(screen.getByText("2 from cache")).toBeInTheDocument()
  })

  it("shows nothing about cache hits when absent", () => {
    mockEventsState = { ...initialAnalysisEventsState, progress: { done: 2, total: 4 } }
    render(<ExportRunning projectId="p1" exportId="e1" onEnd={() => {}} />)

    expect(screen.queryByText(/from cache/)).not.toBeInTheDocument()
  })

  it("shows the problem's title and detail when cancelling fails", async () => {
    vi.mocked(cancelExport).mockRejectedValue(
      new ApiError(500, { type: "about:blank", title: "cancel export", status: 500, detail: "queue is closed" }),
    )
    mockEventsState = { ...initialAnalysisEventsState, progress: { done: 1, total: 4 } }
    render(<ExportRunning projectId="p1" exportId="e1" onEnd={() => {}} />)

    fireEvent.click(screen.getByRole("button", { name: "Cancel" }))

    expect(await screen.findByText("cancel export")).toBeInTheDocument()
    expect(screen.getByText("queue is closed")).toBeInTheDocument()
  })
})
