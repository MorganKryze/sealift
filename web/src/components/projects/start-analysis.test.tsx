import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { fireEvent, render, screen } from "@testing-library/react"
import type { ReactNode } from "react"
import { beforeEach, describe, expect, it, vi } from "vitest"

import { queueAnalysis, type Analysis, type Project } from "@/api/projects"
import { ProjectPage } from "@/components/projects/project-page"

const navigate = vi.hoisted(() => vi.fn())

vi.mock("@tanstack/react-router", () => ({
  Link: ({ children }: { children: ReactNode }) => <a>{children}</a>,
  useNavigate: () => navigate,
}))
vi.mock("@/api/projects", async () => {
  const actual = await vi.importActual<typeof import("@/api/projects")>("@/api/projects")
  return { ...actual, queueAnalysis: vi.fn() }
})

const empty = { id: "audit-cancel", name: "audit-cancel", ecosystem: "npm", createdAt: "2026-11-24T10:14:00Z", analyses: [], exports: [] } as unknown as Project

function renderPage() {
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })}>
      <ProjectPage project={empty} />
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  navigate.mockReset()
  vi.mocked(queueAnalysis).mockReset().mockResolvedValue({ id: "20261127T070000Z", projectId: "audit-cancel", state: "queued" } as unknown as Analysis)
})

describe("a project with no analysis", () => {
  it("starts an analysis of the project's current files and opens it", async () => {
    renderPage()
    expect(screen.getByText("No crossing yet")).toBeInTheDocument()
    fireEvent.click(screen.getByRole("button", { name: "Analyse" }))
    await vi.waitFor(() => expect(queueAnalysis).toHaveBeenCalledWith("audit-cancel"))
    await vi.waitFor(() => expect(navigate).toHaveBeenCalledWith({ to: "/crossings/$projectId", params: { projectId: "audit-cancel" }, search: { analysis: "20261127T070000Z" } }))
  })

  it("says when the analysis did not start", async () => {
    vi.mocked(queueAnalysis).mockRejectedValue(new Error("busy"))
    renderPage()
    fireEvent.click(screen.getByRole("button", { name: "Analyse" }))
    expect(await screen.findByRole("alert")).toHaveTextContent("Analysis did not start")
    expect(navigate).not.toHaveBeenCalled()
  })
})
