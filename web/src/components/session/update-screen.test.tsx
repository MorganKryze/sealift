import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react"
import type { ReactNode } from "react"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import type { Analysis, Export, Project, ProjectSummary } from "@/api/projects"
import { AnalysisScreen } from "@/components/session/analysis-screen"
import { ExportScreen } from "@/components/session/export-screen"
import { UpdateScreen } from "@/components/session/update-screen"
import { initialAnalysisEventsState } from "@/lib/analysisEvents"

const navigate = vi.fn()

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
const created = { id: "web-portal-1a2b3c", name: "web-portal", ecosystem: "npm", target, analyses: [], exports: [] }

// A 40-character name, as the design rules' worst case asks.
const LONG = "customer-onboarding-portal-frontend-next"

const pinned = (count: number, prefix: string) =>
  Object.fromEntries(Array.from({ length: count }, (_, i) => [`${prefix}-${String(i).padStart(3, "0")}`, `1.${i}.0`]))
const ranged = (count: number) => Object.fromEntries(Array.from({ length: count }, (_, i) => [`lib-${String(i).padStart(3, "0")}`, `^2.${i}.0`]))

const COMPLIANT = { name: LONG, dependencies: pinned(139, "dep"), devDependencies: pinned(11, "tool") }
const ISSUES = {
  name: "billing-api",
  dependencies: {
    ...pinned(76, "dep"),
    express: "^4.18.2",
    lodash: "~4.17.21",
    pino: ">=9.0.0",
    "@billing/shared-schemas": "git+ssh://git@gitlab.example.com/billing/shared-schemas.git#v3.2.0",
    "pdf-templates": "file:../pdf-templates",
  },
  devDependencies: pinned(3, "tool"),
  pnpm: { overrides: { semver: "7.5.4", "tough-cookie": "4.1.3", ws: "8.17.1" } },
}

let duplicates: ProjectSummary[] = []
let startProject: () => Promise<Response>
const fetchSpy = vi.fn<(input: RequestInfo | URL, init?: RequestInit) => Promise<Response>>()

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": status < 300 ? "application/json" : "application/problem+json" } })

beforeEach(() => {
  navigate.mockReset()
  duplicates = []
  startProject = () => Promise.resolve(json(created, 201))
  fetchSpy.mockReset()
  fetchSpy.mockImplementation((input, init) => {
    const url = String(input)
    const method = init?.method ?? "GET"
    if (method === "GET" && url.startsWith("/api/projects?manifestSha256=")) return Promise.resolve(json(duplicates))
    if (method === "GET" && url === "/api/settings") return Promise.resolve(json({ target }))
    if (method === "POST" && url === "/api/projects") return startProject()
    return Promise.reject(new Error(`unexpected request ${method} ${url}`))
  })
  vi.stubGlobal("fetch", fetchSpy)
})

afterEach(() => {
  vi.unstubAllGlobals()
})

function withClient(ui: ReactNode) {
  return render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>{ui}</QueryClientProvider>)
}

const FOUR_DAYS = 4 * 86_400_000

function drop(container: HTMLElement, content: object | string, name = "package.json") {
  const input = container.querySelector('input[type="file"]') as HTMLInputElement
  const text = typeof content === "string" ? content : JSON.stringify(content)
  const file = new File([text], name, { type: "application/json", lastModified: Date.now() - FOUR_DAYS })
  fireEvent.change(input, { target: { files: [file] } })
}

const requests = () => fetchSpy.mock.calls.map(([input, init]) => `${init?.method ?? "GET"} ${String(input)}`)
const analyse = () => screen.getByRole("button", { name: /^Analyse$/ })

describe("Update, the Check step", () => {
  it("sends nothing before Analyse", async () => {
    const { container } = withClient(<UpdateScreen />)
    expect(screen.getByText(/^Drop a/)).toHaveTextContent("Drop a package.json")
    expect(screen.getAllByRole("button").filter((b) => !b.closest("nav"))).toHaveLength(1)
    expect(screen.getByRole("button", { name: "Choose file" })).toBeInTheDocument()
    const steps = screen.getByRole("navigation", { name: "Session steps" })
    expect(steps.querySelector('[aria-current="step"]')).toHaveTextContent("Check")

    drop(container, COMPLIANT)
    fireEvent.click(await screen.findByRole("button", { name: "Compliant" }))
    fireEvent.click(screen.getByRole("button", { name: /^150 packages/ }))
    fireEvent.click(screen.getByRole("button", { name: "Show all 150 packages" }))

    const lookups = requests().filter((r) => r.includes("manifestSha256="))
    expect(lookups).toHaveLength(1)
    expect(lookups[0]).toMatch(/^GET \/api\/projects\?manifestSha256=[0-9a-f]{64}$/)
    expect(requests().filter((r) => !r.includes("manifestSha256="))).toEqual(["GET /api/settings"])

    fireEvent.click(analyse())
    await waitFor(() => expect(requests()).toContain("POST /api/projects"))
  })

  it("names a wrong file and what to drop", async () => {
    const { container } = withClient(<UpdateScreen />)
    drop(container, "PK", "kiosk-ui-export.zip")

    const alert = await screen.findByRole("alert")
    expect(alert).toHaveTextContent("kiosk-ui-export.zip is not a package.json")
    expect(alert).toHaveTextContent("Drop the package.json at your project's root; nothing was sent.")
    expect(screen.getByRole("button", { name: "Choose file" })).toBeInTheDocument()

    drop(container, "{ not json")
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("package.json is not valid JSON"))
    expect(requests().filter((r) => r.includes("manifestSha256="))).toEqual([])
  })

  it("refuses a file with no dependency at the drop", async () => {
    const { container } = withClient(<UpdateScreen />)
    drop(container, { name: "empty-app" })

    const alert = await screen.findByRole("alert")
    expect(alert).toHaveTextContent("package.json lists no dependency")
    expect(alert).toHaveTextContent("Drop the package.json of a project with dependencies; nothing was sent.")
    expect(screen.queryByRole("heading", { level: 1, name: /empty-app/ })).toBeNull()
  })

  it("writes the target under the title", async () => {
    const { container } = withClient(<UpdateScreen />)
    drop(container, COMPLIANT)

    const title = await screen.findByRole("heading", { level: 1, name: `Update ${LONG}` })
    await waitFor(() => expect(title.nextElementSibling).toHaveTextContent("npm · Node 22.17.1 · linux x64"))
    expect(screen.getByText("4 days ago")).toHaveClass("figure")
    expect(screen.getByText("4 days ago").parentElement).toHaveTextContent("modified 4 days ago")
  })

  it("shows Compliant only when every check passes", async () => {
    const view = withClient(<UpdateScreen />)
    drop(view.container, COMPLIANT)
    const chip = await screen.findByRole("button", { name: "Compliant" })
    expect(chip).toHaveAttribute("aria-expanded", "false")
    expect(chip).toHaveClass("tinted-ok")
    expect(analyse()).not.toHaveAttribute("aria-disabled")
    view.unmount()

    const one = withClient(<UpdateScreen />)
    drop(one.container, { ...COMPLIANT, dependencies: { ...COMPLIANT.dependencies, express: "^4.18.2" } })
    const warn = await screen.findByRole("button", { name: "1 issue" })
    expect(warn).toHaveAttribute("aria-expanded", "true")
    expect(warn).toHaveClass("tinted-warn")
    expect(screen.queryByText("Compliant")).toBeNull()
  })

  it("opens three checks with their evidence", async () => {
    const { container } = withClient(<UpdateScreen />)
    drop(container, COMPLIANT)
    expect(screen.queryByText("3 checks passed")).toBeNull()

    const chip = await screen.findByRole("button", { name: "Compliant" })
    fireEvent.click(chip)
    expect(chip).toHaveAttribute("aria-expanded", "true")
    const list = screen.getByRole("list", { name: "3 checks passed" })
    expect(within(list).getAllByRole("listitem").map((row) => row.textContent)).toEqual([
      "Exact versions150 of 150 pinned",
      "Registry only150 of 150 on npm",
      "Supported fieldsdependencies · devDependencies",
    ])
  })

  it("opens 30 packages, then Show all", async () => {
    const { container } = withClient(<UpdateScreen />)
    drop(container, COMPLIANT)

    const count = await screen.findByRole("button", { name: /^150 packages/ })
    expect(count).toHaveTextContent("150 packages139 dependencies · 11 devDependencies")
    expect(count).toHaveAttribute("aria-expanded", "false")
    fireEvent.click(count)
    expect(within(screen.getByRole("list", { name: "Packages" })).getAllByRole("listitem")).toHaveLength(30)
    fireEvent.click(screen.getByRole("button", { name: "Show all 150 packages" }))
    const rows = within(screen.getByRole("list", { name: "Packages" })).getAllByRole("listitem")
    expect(rows).toHaveLength(150)
    expect(rows[0]).toHaveTextContent("dep-0001.0.0")
    expect(screen.queryByRole("button", { name: /^Show all/ })).toBeNull()
  })

  it("opens an amber row per failing check with its count and fix", async () => {
    const { container } = withClient(<UpdateScreen />)
    drop(container, ISSUES)

    const exact = await screen.findByRole("group", { name: "Exact versions" })
    expect(exact).toHaveClass("tinted-warn")
    expect(exact).toHaveTextContent("3 of 84 are ranges")
    expect(exact).toHaveTextContent("Write the version you run, such as 4.18.2.")
    expect(within(exact).getAllByRole("listitem").map((row) => row.textContent)).toEqual(["express^4.18.2", "lodash~4.17.21", "pino>=9.0.0"])

    const registry = screen.getByRole("group", { name: "Registry only" })
    expect(registry).toHaveTextContent("2 of 84 off npm")
    expect(registry).toHaveTextContent("git+ssh://git@gitlab.example.com/billing/shared-schemas.git#v3.2.0")

    const fields = screen.getByRole("group", { name: "Supported fields" })
    expect(fields).toHaveTextContent("1 field not supported")
    expect(fields).toHaveTextContent("pnpm.overridessemver, tough-cookie, ws")

    expect(screen.getByRole("button", { name: "3 issues" })).toHaveAttribute("aria-expanded", "true")
  })

  it("lists the first 15 ranges, then Show all, and keeps a passing check green", async () => {
    const { container } = withClient(<UpdateScreen />)
    drop(container, { name: "kiosk-ui", dependencies: ranged(150) })

    const exact = await screen.findByRole("group", { name: "Exact versions" })
    expect(exact).toHaveTextContent("150 of 150 are ranges")
    expect(within(exact).getAllByRole("listitem")).toHaveLength(15)
    fireEvent.click(within(exact).getByRole("button", { name: "Show all 150 packages" }))
    expect(within(exact).getAllByRole("listitem")).toHaveLength(150)

    const passing = screen.getByText("Registry only").closest("li") as HTMLElement
    expect(passing).toHaveTextContent("Registry only150 of 150 on npm")
    expect(passing.querySelector("svg.lucide-check")).not.toBeNull()
    expect(screen.getByText("1 check to fix first")).toBeInTheDocument()
  })

  it("names the checks to fix before Analyse", async () => {
    const { container } = withClient(<UpdateScreen />)
    drop(container, ISSUES)

    const button = await screen.findByRole("button", { name: /^Analyse$/ })
    expect(button).toHaveAttribute("aria-disabled", "true")
    const reason = screen.getByText("3 checks to fix first")
    expect(button).toHaveAccessibleDescription("3 checks to fix first")
    expect(reason.compareDocumentPosition(button) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    fireEvent.click(button)
    expect(requests()).not.toContain("POST /api/projects")
  })

  it("says Starting and disables Replace", async () => {
    startProject = () => new Promise(() => {})
    const { container } = withClient(<UpdateScreen />)
    drop(container, COMPLIANT)
    fireEvent.click(await screen.findByRole("button", { name: /^Analyse$/ }))

    const starting = await screen.findByRole("button", { name: "Starting" })
    expect(starting).toHaveAttribute("aria-busy", "true")
    expect(screen.getByRole("button", { name: "Replace" })).toBeDisabled()
    fireEvent.click(starting)
    expect(requests().filter((r) => r === "POST /api/projects")).toHaveLength(1)
  })

  it("puts Retry in the red block in place of Analyse", async () => {
    startProject = () => Promise.resolve(json({ type: "about:blank", title: "Service Unavailable", status: 503 }, 503))
    const { container } = withClient(<UpdateScreen />)
    drop(container, COMPLIANT)
    fireEvent.click(await screen.findByRole("button", { name: /^Analyse$/ }))

    const alert = await screen.findByRole("alert")
    expect(alert).toHaveClass("tinted-bad")
    expect(alert).toHaveTextContent("Analysis did not start")
    expect(alert).toHaveTextContent("No answer from this instance; your file is still here.")
    const retry = within(alert).getByRole("button", { name: "Retry" })
    expect(retry.parentElement?.lastElementChild).toBe(retry)
    expect(screen.queryByRole("button", { name: /^Analyse$/ })).toBeNull()
    expect(screen.getByText("See your administrators")).toBeInTheDocument()
    expect(alert.compareDocumentPosition(screen.getByText("See your administrators")) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()

    startProject = () => Promise.resolve(json(created, 201))
    fireEvent.click(retry)
    await waitFor(() => expect(navigate).toHaveBeenCalledWith({ to: "/sessions/$sessionId/analysis", params: { sessionId: created.id } }))
  })

  it("offers to open the crossing a byte-identical file had", async () => {
    duplicates = [past]
    const { container } = withClient(<UpdateScreen />)
    drop(container, COMPLIANT)

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

  it("offers Retry for a tools failure and names its first line", () => {
    withClient(
      <AnalysisScreen
        projectId="p1"
        project={project}
        analysis={{ id: "20261124T101500Z", state: "failed", failure: { step: "scan", message: "trivy: exit status 1" } } as unknown as Analysis}
        onChanged={noop}
        onNavigateStep={noop}
      />,
    )

    expect(screen.getByText("trivy: exit status 1")).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument()
    expect(screen.queryByRole("link", { name: "Open Instance" })).toBeNull()
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
