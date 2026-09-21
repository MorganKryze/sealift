import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { createMemoryHistory, createRootRoute, createRouter, RouterProvider } from "@tanstack/react-router"
import { fireEvent, render, screen, waitFor } from "@testing-library/react"
import { beforeEach, describe, expect, it, vi } from "vitest"

import { ProblemError } from "@/api/client"
import { queueExport } from "@/api/projects"
import { ExportLaunch } from "@/components/projects/export-launch"

vi.mock("@/api/projects", async () => {
  const actual = await vi.importActual<typeof import("@/api/projects")>("@/api/projects")
  return { ...actual, queueExport: vi.fn() }
})

// A missing signature key renders a Link to Settings, which needs a router
// context: a minimal router with one route, rendering ExportLaunch itself,
// is enough without pulling in the app's own route tree.
function renderLaunch(analysisId: string) {
  const queryClient = new QueryClient()
  const rootRoute = createRootRoute({
    component: () => (
      <QueryClientProvider client={queryClient}>
        <ExportLaunch
          projectId="p1"
          analysisId={analysisId}
          analysisCreatedAt={new Date().toISOString()}
          onQueued={() => {}}
        />
      </QueryClientProvider>
    ),
  })
  const router = createRouter({ routeTree: rootRoute, history: createMemoryHistory() })
  return render(<RouterProvider router={router} />)
}

beforeEach(() => {
  sessionStorage.clear()
  vi.mocked(queueExport).mockReset()
})

describe("ExportLaunch", () => {
  it("blocks launch when nothing is selected", async () => {
    renderLaunch("a-empty")

    expect(await screen.findByText("Nothing selected yet.")).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Launch export" })).toBeDisabled()
  })

  it("groups the selection by dependency and enables launch", async () => {
    sessionStorage.setItem("sealift:selection:a-grouped", JSON.stringify({ "left-pad": ["1.3.0", "1.4.0"] }))
    renderLaunch("a-grouped")

    expect(await screen.findByText("left-pad")).toBeInTheDocument()
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
    fireEvent.click(await screen.findByRole("button", { name: "Launch export" }))

    await waitFor(() => {
      expect(screen.getAllByText(/not a resolved candidate/).length).toBe(2)
    })
    expect(screen.queryByText("Go to Settings")).not.toBeInTheDocument()
  })

  it("offers Settings only for the missing signature key", async () => {
    sessionStorage.setItem("sealift:selection:a-key", JSON.stringify({ "left-pad": ["1.3.0"] }))
    vi.mocked(queueExport).mockRejectedValue(
      new ProblemError(400, {
        type: "about:blank",
        title: "queue export",
        status: 400,
        detail: "jobs: signatureKey is empty, set it in settings before exporting",
      }),
    )

    renderLaunch("a-key")
    fireEvent.click(await screen.findByRole("button", { name: "Launch export" }))

    expect(await screen.findByText("Go to Settings")).toBeInTheDocument()
  })

  it("does not offer Settings for an unrelated failure", async () => {
    sessionStorage.setItem("sealift:selection:a-500", JSON.stringify({ "left-pad": ["1.3.0"] }))
    vi.mocked(queueExport).mockRejectedValue(
      new ProblemError(500, { type: "about:blank", title: "queue export", status: 500, detail: "internal error" }),
    )

    renderLaunch("a-500")
    fireEvent.click(await screen.findByRole("button", { name: "Launch export" }))

    await waitFor(() => {
      expect(screen.getByText("internal error")).toBeInTheDocument()
    })
    expect(screen.queryByText("Go to Settings")).not.toBeInTheDocument()
  })
})
