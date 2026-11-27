import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render, screen, within } from "@testing-library/react"
import type { ComponentType } from "react"
import { beforeEach, describe, expect, it, vi } from "vitest"

import { getProject, type Project } from "@/api/projects"
import { Route } from "@/routes/crossings.$projectId"

const search = vi.hoisted(() => ({ current: {} as Record<string, string> }))

vi.mock("@tanstack/react-router", () => ({
  createFileRoute: () => (options: object) => ({ options, useParams: () => ({ projectId: "demo" }), useSearch: () => search.current }),
  useNavigate: () => vi.fn(),
}))
vi.mock("@/api/projects", async () => {
  const actual = await vi.importActual<typeof import("@/api/projects")>("@/api/projects")
  return { ...actual, getProject: vi.fn() }
})
vi.mock("@/components/session/review-screen", () => ({ ReviewScreen: () => <p>review screen</p> }))
vi.mock("@/components/session/export-screen", () => ({ ExportScreen: () => <p>export screen</p> }))
vi.mock("@/components/session/analysis-screen", () => ({ AnalysisScreen: () => <p>analysis screen</p> }))

const target = { os: "linux", cpu: "x64", libc: "glibc", node: "22.17.1", pnpmVer: "12.3.4" }
const sealed = {
  id: "demo",
  name: "kiosk-ui",
  target,
  createdAt: "2026-11-24T10:14:00Z",
  analyses: [{ id: "20261124T101500Z", projectId: "demo", state: "done", createdAt: "2026-11-24T10:15:00Z", result: { target, before: [0, 0, 0, 0, 0], dependencies: [], warnings: [] } }],
  exports: [{ id: "20261124T102000Z", projectId: "demo", analysisId: "20261124T101500Z", state: "done", createdAt: "2026-11-24T10:20:00Z" }],
} as unknown as Project

function renderCrossing() {
  const Crossing = (Route as unknown as { options: { component: ComponentType } }).options.component
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <Crossing />
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  vi.mocked(getProject).mockReset().mockResolvedValue(sealed)
})

describe("the crossing route", () => {
  it("offers Analyse on the Check step of a project with no analysis", async () => {
    search.current = {}
    vi.mocked(getProject).mockResolvedValue({ ...sealed, analyses: [], exports: [] } as unknown as Project)
    renderCrossing()
    expect(await screen.findByRole("button", { name: "Analyse" })).toBeInTheDocument()
  })

  it("opens Seal on a crossing whose export is done", async () => {
    search.current = {}
    renderCrossing()
    expect(await screen.findByText("export screen")).toBeInTheDocument()
  })

  it("opens Review on a sealed crossing when the address names the review step", async () => {
    search.current = { step: "review" }
    renderCrossing()
    expect(await screen.findByText("review screen")).toBeInTheDocument()
    expect(screen.queryByText("export screen")).toBeNull()
  })
})

describe("the Check step bar on an earlier crossing", () => {
  it("follows the analysis the address names, not a later cancelled one", async () => {
    const later = { id: "20261125T090000Z", projectId: "demo", state: "cancelled", createdAt: "2026-11-25T09:00:00Z" }
    vi.mocked(getProject).mockResolvedValue({ ...sealed, analyses: [...sealed.analyses!, later] } as unknown as Project)
    search.current = { analysis: "20261124T101500Z", step: "check" }
    renderCrossing()
    const nav = await screen.findByRole("navigation", { name: "Session steps" })
    expect(within(nav).queryByText(", cancelled")).toBeNull()
    expect(within(nav).getByRole("button", { name: /Review/ })).toBeDefined()
  })
})
