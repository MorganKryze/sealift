import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { fireEvent, render, screen, waitFor } from "@testing-library/react"
import { describe, expect, it, vi } from "vitest"

import { FailureBlock } from "@/components/failure-block"

function renderBlock() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={queryClient}>
      <FailureBlock
        projectId="p1"
        analysisId="a1"
        message="sealift could not download the vulnerability database."
        detail="Your file is kept; retrying starts again from the scan."
        actions={<button>Retry from the scan</button>}
      />
    </QueryClientProvider>,
  )
}

describe("FailureBlock", () => {
  it("shows the cause and the next action without fetching the log", () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch")
    renderBlock()

    expect(screen.getByText(/could not download the vulnerability database/)).toBeInTheDocument()
    expect(screen.getByText(/Your file is kept/)).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Retry from the scan" })).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it("fetches the log only once the details are opened, not on mount", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("14:26:40 validate      ok\n14:26:41 scan-project  database update failed", { status: 200 }),
    )
    renderBlock()

    fireEvent.click(screen.getByText("Show the log"))

    await waitFor(() => {
      expect(screen.getByText(/database update failed/)).toBeInTheDocument()
    })
    expect(fetch).toHaveBeenCalledWith("/api/projects/p1/analyses/a1/log")
    expect(fetch).toHaveBeenCalledTimes(1)
  })

  it("reports the problem when the log fails to load", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ title: "not found", status: 404 }), {
        status: 404,
        headers: { "content-type": "application/json" },
      }),
    )
    renderBlock()

    fireEvent.click(screen.getByText("Show the log"))

    await waitFor(() => {
      expect(screen.getByText("Could not load the log.")).toBeInTheDocument()
    })
  })
})
