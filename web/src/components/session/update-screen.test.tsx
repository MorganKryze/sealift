import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { fireEvent, render, screen, within } from "@testing-library/react"
import type { ReactNode } from "react"
import { beforeEach, describe, expect, it, vi } from "vitest"

import { apiFetch } from "@/api/client"
import type { Analysis, Export, Project, ProjectSummary } from "@/api/projects"
import { AnalysisScreen } from "@/components/session/analysis-screen"
import { ExportScreen } from "@/components/session/export-screen"
import { UpdateScreen } from "@/components/session/update-screen"
import { initialAnalysisEventsState } from "@/lib/analysisEvents"

const navigate = vi.fn()

vi.mock("@/api/client", async () => {
  const actual = await vi.importActual<typeof import("@/api/client")>("@/api/client")
  return { ...actual, apiFetch: vi.fn() }
})
vi.mock("@tanstack/react-router", () => ({
  useNavigate: () => navigate,
  Link: ({ to, params, children, ...rest }: { to: string; params?: Record<string, string>; children: ReactNode }) => (
    <a href={Object.entries(params ?? {}).reduce((path, [key, value]) => path.replace(`$${key}`, value), to)} {...rest}>
      {children}
    </a>
  ),
}))
vi.mock("@/hooks/use-job-events", () => ({ useJobEvents: () => initialAnalysisEventsState }))

const target = { os: "linux", cpu: "x64", libc: "glibc", node: "22.17.1", pnpmVer: "10.34.5" } as const
const past: ProjectSummary = {
  id: "left-pad-abc123",
  name: "left-pad",
  ecosystem: "npm",
  target,
  lastAnalysis: { id: "20261124T101500Z", projectId: "left-pad-abc123", state: "done", createdAt: "2026-11-24T10:15:00Z" },
}

let duplicates: ProjectSummary[] = []

beforeEach(() => {
  navigate.mockReset()
  duplicates = []
  vi.mocked(apiFetch).mockReset()
  vi.mocked(apiFetch).mockImplementation((path: string) => {
    if (path.startsWith("/projects?manifestSha256=")) return Promise.resolve(duplicates) as never
    if (path === "/projects") return Promise.resolve([past]) as never
    if (path === "/settings") return Promise.resolve({ target }) as never
    return Promise.reject(new Error(`unexpected request ${path}`))
  })
})

function withClient(ui: ReactNode) {
  return render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>{ui}</QueryClientProvider>)
}

function drop(container: HTMLElement) {
  const input = container.querySelector('input[type="file"]') as HTMLInputElement
  const file = new File([JSON.stringify({ name: "kiosk-ui", dependencies: { express: "5.0.1" } })], "package.json", { type: "application/json" })
  fireEvent.change(input, { target: { files: [file] } })
}

describe("Update, today's drop", () => {
  it("lists no past session", async () => {
    withClient(<UpdateScreen />)

    expect(await screen.findByRole("button", { name: "Choose a file" })).toBeInTheDocument()
    await screen.findByText(/Node 22\.17\.1/)
    expect(screen.queryByText("left-pad")).toBeNull()
    expect(screen.queryByText(/Past sessions/)).toBeNull()
    expect(vi.mocked(apiFetch).mock.calls.map(([path]) => path)).not.toContain("/projects")
  })

  it("numbers the steps and marks the drop as the current one", () => {
    withClient(<UpdateScreen />)

    const steps = screen.getByRole("navigation", { name: "Session steps" })
    expect(steps.querySelector('[aria-current="step"]')).toHaveTextContent("Drop")
  })

  it("opens a dropped manifest's preview and uploads nothing", async () => {
    const { container } = withClient(<UpdateScreen />)
    drop(container)

    expect(await screen.findByRole("button", { name: "Analyse 1 dependency" })).toBeInTheDocument()
    expect(screen.getByText("kiosk-ui")).toBeInTheDocument()
    for (const [, init] of vi.mocked(apiFetch).mock.calls) expect(init?.method ?? "GET").toBe("GET")
  })

  it("offers to resume a session made from the same file", async () => {
    duplicates = [past]
    const { container } = withClient(<UpdateScreen />)
    drop(container)

    const dialog = await screen.findByRole("dialog")
    fireEvent.click(within(dialog).getByRole("button", { name: "Resume that session" }))
    expect(navigate).toHaveBeenCalledWith({ to: "/sessions/$sessionId", params: { sessionId: past.id } })
  })
})

describe("the session pages' actions", () => {
  const project = { id: "p1", name: "kiosk-ui" } as unknown as Project
  const noop = () => {}

  it("draws the export's and the analysis's Cancel as tinted buttons with their icons", () => {
    const view = withClient(
      <AnalysisScreen projectId="p1" project={project} analysis={{ id: "20261124T101500Z", state: "running" } as unknown as Analysis} onChanged={noop} onNavigateStep={noop} />,
    )
    const analysisCancel = screen.getByRole("button", { name: "Cancel" })
    expect(analysisCancel).toHaveClass("bg-hover", "border-rule-2")
    expect(analysisCancel.querySelector("svg")).not.toBeNull()
    view.unmount()

    withClient(
      <ExportScreen
        project={project}
        analysis={{ id: "20261124T101500Z", state: "done" } as unknown as Analysis}
        relatedExport={{ id: "20261124T102000Z", state: "running" } as unknown as Export}
        onChanged={noop}
        onNavigateStep={noop}
      />,
    )
    const exportCancel = screen.getByRole("button", { name: "Cancel" })
    expect(exportCancel).toHaveClass("bg-hover", "border-rule-2")
    expect(exportCancel.querySelector("svg")).not.toBeNull()
  })

  it("links a tools failure to Instance", () => {
    withClient(
      <AnalysisScreen
        projectId="p1"
        project={project}
        analysis={{ id: "20261124T101500Z", state: "failed", failure: { step: "scan", message: "trivy: exit status 1" } } as unknown as Analysis}
        onChanged={noop}
        onNavigateStep={noop}
      />,
    )

    expect(screen.getByRole("link", { name: "Open Instance" })).toHaveAttribute("href", "/instance")
    expect(screen.getByRole("link", { name: "Choose another file" })).toHaveAttribute("href", "/update")
  })

  it("ends a failure's action row with its primary at the right", () => {
    withClient(
      <ExportScreen
        project={project}
        analysis={{ id: "20261124T101500Z", state: "done" } as unknown as Analysis}
        relatedExport={{ id: "20261124T102000Z", state: "failed" } as unknown as Export}
        onChanged={noop}
        onNavigateStep={noop}
      />,
    )
    const retry = screen.getByRole("button", { name: "Retry" })
    expect(retry.parentElement?.lastElementChild).toBe(retry)
    expect(retry.parentElement).toHaveClass("justify-end")
  })
})
