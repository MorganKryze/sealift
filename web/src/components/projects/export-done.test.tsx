import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render, screen, waitFor } from "@testing-library/react"
import { describe, expect, it, vi } from "vitest"

import { ExportDone } from "@/components/projects/export-done"

vi.mock("@/api/client", async () => {
  const actual = await vi.importActual<typeof import("@/api/client")>("@/api/client")
  return {
    ...actual,
    apiFetch: vi.fn().mockResolvedValue({
      sha256: "abc123",
      packageCount: 7,
      files: [{ name: "archive.tgz", size: 2048 }],
    }),
  }
})

function renderDone() {
  const queryClient = new QueryClient()
  render(
    <QueryClientProvider client={queryClient}>
      <ExportDone projectId="p1" exportId="e1" files={["archive.tgz", "manifest.json"]} />
    </QueryClientProvider>,
  )
}

describe("ExportDone", () => {
  it("reads sha256 and package count from the mocked manifest.json", async () => {
    renderDone()

    await waitFor(() => {
      expect(screen.getByText("abc123")).toBeInTheDocument()
    })
    expect(screen.getByText(/7 packages/)).toBeInTheDocument()
    expect(screen.getByText("2.0 KB")).toBeInTheDocument()
  })
})
