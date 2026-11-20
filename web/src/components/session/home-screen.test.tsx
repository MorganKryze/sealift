import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { fireEvent, render, screen } from "@testing-library/react"
import { beforeEach, describe, expect, it, vi } from "vitest"

import { apiFetch } from "@/api/client"
import type { ProjectSummary } from "@/api/projects"
import { HomeScreen } from "@/components/session/home-screen"

const navigate = vi.fn()

vi.mock("@/api/client", async () => {
  const actual = await vi.importActual<typeof import("@/api/client")>("@/api/client")
  return { ...actual, apiFetch: vi.fn() }
})
vi.mock("@tanstack/react-router", () => ({ useNavigate: () => navigate }))

// One row per ecosystem, shaped like the answer of GET /api/projects.
const npmRow: ProjectSummary = {
  id: "left-pad-abc123",
  name: "left-pad",
  ecosystem: "npm",
  target: { os: "linux", cpu: "x64", libc: "glibc", node: "22.17.1", pnpmVer: "10.34.5" },
}
const pipRow: ProjectSummary = {
  id: "data-tools-def456",
  name: "Data tools",
  ecosystem: "pip",
  pipTarget: { python: "3.11.2", os: "linux", cpu: "x86_64", glibc: "2.28", uvVer: "0.13.7" },
}

function renderHome() {
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <HomeScreen />
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  navigate.mockReset()
  vi.mocked(apiFetch).mockReset()
  vi.mocked(apiFetch).mockImplementation((path: string) => {
    if (path.startsWith("/projects")) return Promise.resolve([pipRow, npmRow]) as never
    if (path === "/settings") return Promise.resolve({ target: npmRow.target }) as never
    return Promise.reject(new Error(`unexpected request ${path}`))
  })
})

describe("HomeScreen past sessions", () => {
  it("shows a pip project by name and kind, with no button", async () => {
    renderHome()

    expect(await screen.findByText("Data tools")).toBeInTheDocument()
    expect(screen.getByText("pip project. This release cannot open it yet.")).toBeInTheDocument()
    expect(screen.queryByRole("button", { name: /Data tools/ })).not.toBeInTheDocument()
  })

  it("keeps the npm row's target and opens it on click", async () => {
    renderHome()

    const row = await screen.findByRole("button", { name: /left-pad/ })
    expect(row).toHaveTextContent("linux/x64 · glibc")

    fireEvent.click(row)
    expect(navigate).toHaveBeenCalledWith({ to: "/sessions/$sessionId", params: { sessionId: "left-pad-abc123" } })
  })
})
