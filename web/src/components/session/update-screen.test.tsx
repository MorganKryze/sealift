import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react"
import type { ReactNode } from "react"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import type { Analysis, Export, Project, ProjectSummary } from "@/api/projects"
import { BrandProvider, DEFAULT_BRAND } from "@/components/frame/brand"
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

const pipTarget = { python: "3.11.2", os: "linux", cpu: "x86_64", glibc: "2.28", uvVer: "0.13.7" }
const instance = { brand: { name: "sealift", online: "Online", offline: "Offline", reviewWord: "PR", logo: false }, policy: { target, pipTarget } }
// A 40-character pip project, as the design rules' worst case asks.
const pipProject = { id: "analytics-ingest-1a2b3c", name: "analytics-ingest-pipeline-airflow-worker", ecosystem: "pip", pipTarget, analyses: [], exports: [] }
const createdPip = { id: "ledger-reconciler-4d5e6f", name: "ledger-reconciler", ecosystem: "pip", pipTarget, analyses: [], exports: [] }

// A 60-character package name, as the design rules' worst case asks.
const LONG_PACKAGE = "acme-ledger-reconciliation-opentelemetry-exporter-postgresql"
const rows = (count: number, prefix: string, version: (i: number) => string) => Array.from({ length: count }, (_, i) => `${prefix}-${String(i).padStart(3, "0")}${version(i)}`)
const text = (...lines: string[]) => `${lines.join("\n")}\n`

// The usual project: 94 pins in three files, the dev file including the other two.
const USUAL = {
  "requirements.txt": text(...rows(64, "run-lib", (i) => `==1.${i}.0`)),
  "requirements-dev.txt": text("-r requirements.txt", "-c constraints.txt", ...rows(18, "dev-tool", (i) => `==2.${i}.0`)),
  "constraints.txt": text(...rows(12, "pinned-dep", (i) => `==3.${i}.0`)),
}
// The worst case: 220 pins in three files, the run file written with no version on 142 lines.
const UNPINNED = {
  "requirements.txt": text(LONG_PACKAGE, ...rows(141, "run-lib", () => "")),
  "requirements-dev.txt": text("-r requirements-base.txt", "-r requirements.txt", "-c constraints.txt", ...rows(42, "dev-tool", (i) => `==2.${i}.0`)),
  "constraints.txt": text(...rows(36, "pinned-dep", (i) => `==3.${i}.0`)),
}
const WORST = {
  ...UNPINNED,
  "requirements.txt": text(`${LONG_PACKAGE}==1.4.0`, ...rows(141, "run-lib", (i) => `==1.${i}.0`)),
  "requirements-dev.txt": text("-r requirements.txt", "-c constraints.txt", ...rows(42, "dev-tool", (i) => `==2.${i}.0`)),
}
const ISSUES_PIP = {
  "requirements.txt": text("--index-url https://pypi.internal.example.com/simple", "Django>=4.2,<5", "requests==2.32.3", "-e git+https://github.com/acme/billing-sdk.git@v2.3.1#egg=billing-sdk"),
  "constraints.txt": text("requests==2.31.0"),
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
    if (method === "GET" && url === "/api/instance") return Promise.resolve(json(instance))
    if (method === "GET" && url === `/api/projects/${pipProject.id}`) return Promise.resolve(json(pipProject))
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
    expect(screen.getByText(/^Drop a/)).toHaveTextContent("Drop a package.json or requirements files")
    expect(screen.getAllByRole("button").filter((b) => !b.closest("nav"))).toHaveLength(1)
    expect(screen.getByRole("button", { name: "Choose files" })).toBeInTheDocument()
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
    drop(container, "PK\u0003\u0004", "kiosk-ui-export.zip")

    const alert = await screen.findByRole("alert")
    expect(alert).toHaveTextContent("kiosk-ui-export.zip is not a package.json or a requirements file")
    expect(alert).toHaveTextContent("Drop the package.json at your project's root; nothing was sent.")
    expect(screen.getByRole("button", { name: "Choose files" })).toBeInTheDocument()

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
    await waitFor(() => expect(navigate).toHaveBeenCalledWith({ to: "/crossings/$projectId", params: { projectId: created.id } }))
  })

  it("opens the crossing once the server answers", async () => {
    let answer: (response: Response) => void = () => {}
    startProject = () => new Promise((resolve) => (answer = resolve))
    const { container } = withClient(<UpdateScreen />)
    drop(container, COMPLIANT)
    fireEvent.click(await screen.findByRole("button", { name: /^Analyse$/ }))
    await screen.findByRole("button", { name: "Starting" })
    expect(navigate).not.toHaveBeenCalled()

    answer(json(created, 201))
    await waitFor(() => expect(navigate).toHaveBeenCalledWith({ to: "/crossings/$projectId", params: { projectId: created.id } }))
    expect(navigate).toHaveBeenCalledTimes(1)
  })

  it("offers to open the crossing a byte-identical file had", async () => {
    duplicates = [past]
    const { container } = withClient(<UpdateScreen />)
    drop(container, COMPLIANT)

    const dialog = await screen.findByRole("dialog")
    fireEvent.click(within(dialog).getByRole("button", { name: "Resume that session" }))
    expect(navigate).toHaveBeenCalledWith({ to: "/crossings/$projectId", params: { projectId: past.id } })
  })
})

// Sets files on the zone's input, as a choice or a drop of several files does.
function dropFiles(container: HTMLElement, files: Record<string, string>, input = container.querySelector('input[type="file"]') as HTMLInputElement) {
  const list = Object.entries(files).map(([name, body]) => new File([body], name, { type: "text/plain", lastModified: Date.now() - FOUR_DAYS }))
  fireEvent.change(input, { target: { files: list } })
}

const nameField = () => screen.getByRole("textbox", { name: "Project name" })
const fileRow = (name: string) => screen.getByRole("button", { name: new RegExp(`^${name.replace(/[.]/g, "\\.")}`) })

describe("Update, the Check step for requirements files", () => {
  it("sends nothing before Analyse", async () => {
    const { container } = withClient(<UpdateScreen />)
    dropFiles(container, USUAL)
    fireEvent.click(await screen.findByRole("button", { name: "Compliant" }))
    fireEvent.click(fileRow("requirements-dev.txt"))
    fireEvent.change(nameField(), { target: { value: "ledger-reconciler" } })

    await waitFor(() => expect(requests()).toContain("GET /api/instance"))
    expect(requests().filter((r) => r.includes("manifestSha256="))).toEqual([])
    expect(requests().filter((r) => r.startsWith("POST"))).toEqual([])
  })

  it("refuses a package.json dropped with requirements files", async () => {
    const { container } = withClient(<UpdateScreen />)
    dropFiles(container, { "package.json": JSON.stringify(COMPLIANT), "requirements.txt": "Django==4.2.16\n", "constraints.txt": "idna==3.10\n" })

    const alert = await screen.findByRole("alert")
    expect(alert).toHaveClass("tinted-bad")
    expect(alert).toHaveTextContent("package.json and 2 requirements files dropped together")
    expect(alert).toHaveTextContent("Drop the package.json alone, or the requirements files alone; nothing was sent.")
    expect(screen.getByRole("button", { name: "Choose files" })).toBeInTheDocument()
    expect(requests().filter((r) => r.includes("manifestSha256=") || r.startsWith("POST"))).toEqual([])
  })

  it("refuses more than 32 files or one over 1 MiB", async () => {
    const view = withClient(<UpdateScreen />)
    dropFiles(view.container, Object.fromEntries(Array.from({ length: 33 }, (_, i) => [`requirements-${i}.txt`, "idna==3.10\n"])))
    expect(await screen.findByRole("alert")).toHaveTextContent("33 files dropped; a crossing takes at most 32 requirements files")
    view.unmount()

    const big = withClient(<UpdateScreen />)
    dropFiles(big.container, { "requirements.txt": "idna==3.10\n", "vendored.txt": "#".repeat((1 << 20) + 1) })
    const alert = await screen.findByRole("alert")
    expect(alert).toHaveTextContent("vendored.txt is over 1 MiB, the most a requirements file may hold")
    expect(screen.queryByText(/^\d+ requirements files$/)).toBeNull()
  })

  it("reads requirements files as a pip crossing", async () => {
    const { container } = withClient(<UpdateScreen />)
    dropFiles(container, WORST)

    expect(await screen.findByText("3 requirements files")).toBeInTheDocument()
    expect(screen.getByText("3 requirements files").nextElementSibling).toHaveTextContent("220 pins · modified 4 days ago")
    expect(fileRow("requirements.txt")).toHaveTextContent("requirements.txt142 pins")
    expect(fileRow("requirements-dev.txt")).toHaveTextContent("requirements-dev.txt42 pins-r requirements.txt · -c constraints.txt")
    expect(fileRow("constraints.txt")).toHaveTextContent("constraints.txt36 constraints")
    for (const name of ["requirements.txt", "requirements-dev.txt", "constraints.txt"]) expect(fileRow(name)).toHaveAttribute("aria-expanded", "false")
    expect(screen.getByRole("button", { name: "Compliant" })).toHaveAttribute("aria-expanded", "false")
    expect(screen.getByRole("navigation", { name: "Session steps" }).querySelector('[aria-current="step"]')).toHaveTextContent("Check")
  })

  it("writes the pip target under the title", async () => {
    const { container } = withClient(<UpdateScreen />)
    dropFiles(container, USUAL)
    await screen.findByText("3 requirements files")

    const title = screen.getByRole("heading", { level: 1 })
    await waitFor(() => expect(title.nextElementSibling).toHaveTextContent("pip · Python 3.11.2 · linux x86_64 · glibc 2.28"))
  })

  it("asks the name in the title and focuses it", async () => {
    const { container } = withClient(<UpdateScreen />)
    dropFiles(container, USUAL)

    const field = await screen.findByRole("textbox", { name: "Project name" })
    expect(screen.getByRole("heading", { level: 1 })).toContainElement(field)
    expect(field).toHaveValue("")
    await waitFor(() => expect(field).toHaveFocus())
    const button = analyse()
    expect(button).toHaveAttribute("aria-disabled", "true")
    expect(button).toHaveAccessibleDescription("Name the project first")
    const reason = screen.getByText("Name the project first")
    expect(reason.compareDocumentPosition(button) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
  })

  it("keeps Analyse disabled until the name has a letter or digit", async () => {
    const { container } = withClient(<UpdateScreen />)
    dropFiles(container, USUAL)
    const field = await screen.findByRole("textbox", { name: "Project name" })

    fireEvent.change(field, { target: { value: "   " } })
    expect(analyse()).toHaveAccessibleDescription("Name the project first")
    fireEvent.change(field, { target: { value: "-- __ .." } })
    expect(analyse()).toHaveAttribute("aria-disabled", "true")
    expect(analyse()).toHaveAccessibleDescription("Use a letter or a digit in the name")
    fireEvent.click(analyse())
    expect(requests()).not.toContain("POST /api/projects")

    fireEvent.change(field, { target: { value: "ledger-reconciler" } })
    expect(analyse()).not.toHaveAttribute("aria-disabled")
    expect(field).toHaveAttribute("maxLength", "100")
  })

  it("titles a new crossing of a pip project with its name and no field", async () => {
    const { container } = withClient(<UpdateScreen from={pipProject.id} />)
    dropFiles(container, USUAL)

    expect(await screen.findByRole("heading", { level: 1, name: `Update ${pipProject.name}` })).toBeInTheDocument()
    expect(screen.queryByRole("textbox", { name: "Project name" })).toBeNull()
    expect(analyse()).not.toHaveAttribute("aria-disabled")
  })

  it("explains the target with its two commands", async () => {
    const view = render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <BrandProvider brand={{ ...DEFAULT_BRAND, offline: "Air-gapped" }}>
          <UpdateScreen from={pipProject.id} />
        </BrandProvider>
      </QueryClientProvider>,
    )
    dropFiles(view.container, USUAL)

    const button = await screen.findByRole("button", { name: "What the target is" })
    expect(button).toHaveAttribute("aria-expanded", "false")
    expect(screen.queryByText("Check on one of them")).toBeNull()
    expect(screen.getAllByRole("button", { name: /^What the/ })).toHaveLength(1)

    fireEvent.click(button)
    expect(button).toHaveAttribute("aria-expanded", "true")
    const popover = document.getElementById(button.getAttribute("aria-controls") ?? "") as HTMLElement
    expect(popover).toHaveTextContent("The Python and system of your Air-gapped machines. Each package crosses as the wheel they install.")
    expect(popover).toHaveTextContent("Check on one of them")
    expect(within(popover).getByText("python3 -VV").nextElementSibling).toHaveTextContent("Python 3.11.2")
    expect(within(popover).getByText("ldd --version").nextElementSibling).toHaveTextContent("ldd (GNU libc) 2.28")
    const more = within(popover).getByRole("link", { name: "Read more" })
    expect(more).toHaveAttribute("href", "https://github.com/MorganKryze/sealift/blob/main/docs/python.md#the-target")
    expect(more).toHaveAttribute("rel", "noopener noreferrer")

    fireEvent.keyDown(button, { key: "Escape" })
    expect(button).toHaveAttribute("aria-expanded", "false")
    expect(button).toHaveFocus()
  })

  it("opens five checks and a file's pins", async () => {
    const { container } = withClient(<UpdateScreen />)
    dropFiles(container, WORST)

    fireEvent.click(await screen.findByRole("button", { name: "Compliant" }))
    expect(within(screen.getByRole("list", { name: "5 checks passed" })).getAllByRole("listitem").map((row) => row.textContent)).toEqual([
      "Exact versions220 of 220 pinned with ==",
      "PyPI only220 of 220 on PyPI",
      "Supported options-r · -c",
      "Included files2 of 2 dropped",
      "One version each3 files agree",
    ])

    const row = fileRow("requirements.txt")
    fireEvent.click(row)
    expect(row).toHaveAttribute("aria-expanded", "true")
    const pins = () => within(screen.getByRole("list", { name: "Pins in requirements.txt" })).getAllByRole("listitem")
    expect(pins()).toHaveLength(30)
    expect(pins()[0]).toHaveTextContent(`${LONG_PACKAGE}1.4.0`)
    fireEvent.click(screen.getByRole("button", { name: "Show all 142 pins" }))
    expect(pins()).toHaveLength(142)
  })

  it("opens an amber row per failing check with each line and file:line", async () => {
    const view = withClient(<UpdateScreen />)
    dropFiles(view.container, ISSUES_PIP)

    const chip = await screen.findByRole("button", { name: "4 issues" })
    expect(chip).toHaveAttribute("aria-expanded", "true")
    expect(chip).toHaveClass("tinted-warn")
    const exact = screen.getByRole("group", { name: "Exact versions" })
    expect(exact).toHaveClass("tinted-warn")
    expect(exact).toHaveTextContent("1 of 3 not pinned with ==")
    expect(exact).toHaveTextContent("Pin the version you run, such as Django==4.2.16; pip freeze prints them.")
    expect(within(exact).getAllByRole("listitem").map((r) => r.textContent)).toEqual(["Django>=4.2,<5"])
    expect(within(exact).getByRole("list", { name: "Lines in requirements.txt" })).toBeInTheDocument()
    expect(exact).toHaveTextContent("requirements.txt 1 line")
    expect(screen.getByRole("group", { name: "PyPI only" })).toHaveTextContent("billing-sdk-e git+https://github.com/acme/billing-sdk.git@v2.3.1#egg=billing-sdkrequirements.txt:4")
    expect(screen.getByRole("group", { name: "Supported options" })).toHaveTextContent("--index-urlhttps://pypi.internal.example.com/simplerequirements.txt:1")
    expect(within(screen.getByRole("group", { name: "One version each" })).getAllByRole("listitem").map((r) => r.textContent)).toEqual([
      "requests2.32.3requirements.txt:3",
      "2.31.0constraints.txt:1",
    ])
    const passing = screen.getByText("Included files").closest("li") as HTMLElement
    expect(passing).toHaveTextContent("Included filesNo file includes another")
    expect(passing.querySelector("svg.lucide-check")).not.toBeNull()
    expect(analyse()).toHaveAttribute("aria-disabled", "true")
    expect(analyse()).toHaveAccessibleDescription("4 checks to fix first")
    view.unmount()

    const worst = withClient(<UpdateScreen />)
    dropFiles(worst.container, UNPINNED)
    const unpinned = await screen.findByRole("group", { name: "Exact versions" })
    expect(unpinned).toHaveTextContent("142 of 220 not pinned with ==")
    expect(within(unpinned).getAllByRole("listitem")).toHaveLength(15)
    expect(within(unpinned).getAllByRole("listitem")[0]).toHaveTextContent(`${LONG_PACKAGE}no version`)
    expect(unpinned).toHaveTextContent("requirements.txt 142 lines")
    fireEvent.click(within(unpinned).getByRole("button", { name: "Show all 142 lines" }))
    expect(within(unpinned).getAllByRole("listitem")).toHaveLength(142)
  })

  it("adds a missing included file", async () => {
    const { container } = withClient(<UpdateScreen from={pipProject.id} />)
    dropFiles(container, { ...WORST, "requirements-dev.txt": UNPINNED["requirements-dev.txt"] })

    const included = await screen.findByRole("group", { name: "Included files" })
    expect(included).toHaveTextContent("1 of 3 not dropped")
    expect(within(included).getAllByRole("listitem").map((r) => r.textContent)).toEqual(["-rrequirements-base.txtrequirements-dev.txt:1"])
    const chooser = container.querySelector('input[type="file"][data-add-files]') as HTMLInputElement
    const click = vi.spyOn(chooser, "click").mockImplementation(() => {})
    fireEvent.click(within(included).getByRole("button", { name: "Add file" }))
    expect(click).toHaveBeenCalledTimes(1)

    dropFiles(container, { "requirements-base.txt": text("idna==3.10") }, chooser)
    expect(await screen.findByText("4 requirements files")).toBeInTheDocument()
    expect(screen.getByText("4 requirements files").nextElementSibling).toHaveTextContent("221 pins")
    expect(screen.getByRole("button", { name: "Compliant" })).toBeInTheDocument()
    expect(analyse()).not.toHaveAttribute("aria-disabled")
  })

  it("sends the name and files", async () => {
    let answer: (response: Response) => void = () => {}
    startProject = () => new Promise((resolve) => (answer = resolve))
    const { container } = withClient(<UpdateScreen />)
    dropFiles(container, USUAL)
    fireEvent.change(await screen.findByRole("textbox", { name: "Project name" }), { target: { value: "  ledger-reconciler " } })
    fireEvent.click(analyse())

    const starting = await screen.findByRole("button", { name: "Starting" })
    expect(starting).toHaveAttribute("aria-busy", "true")
    expect(screen.getByRole("button", { name: "Replace" })).toBeDisabled()
    const posts = fetchSpy.mock.calls.filter(([input, init]) => String(input) === "/api/projects" && init?.method === "POST")
    expect(posts).toHaveLength(1)
    const body = posts[0][1]?.body as FormData
    expect([...body.keys()].sort()).toEqual(["ecosystem", "name", "requirements", "requirements", "requirements"])
    expect(body.get("ecosystem")).toBe("pip")
    expect(body.get("name")).toBe("ledger-reconciler")
    expect(body.getAll("requirements").map((file) => (file as File).name)).toEqual(["requirements.txt", "requirements-dev.txt", "constraints.txt"])
    expect(body.has("pipTarget")).toBe(false)

    answer(json(createdPip, 201))
    await waitFor(() => expect(navigate).toHaveBeenCalledWith({ to: "/crossings/$projectId", params: { projectId: createdPip.id } }))
  })

  it("lists the server's problems with Replace files", async () => {
    startProject = () =>
      Promise.resolve(
        json(
          {
            type: "about:blank",
            title: "invalid requirements files",
            status: 400,
            detail: "the requirements files have lines sealift cannot analyze",
            errors: [
              { field: "requirements.txt", line: 7, value: 'numpy==2.1.3 ; platform_machine == "x86_64" or {x}', reason: "marker has characters outside letters, digits, spaces and _.<>=!~\"'()-" },
              { field: "constraints.txt", reason: "file has more than 10000 lines" },
            ],
          },
          400,
        ),
      )
    const { container } = withClient(<UpdateScreen from={pipProject.id} />)
    dropFiles(container, USUAL)
    fireEvent.click(await screen.findByRole("button", { name: /^Analyse$/ }))

    const alert = await screen.findByRole("alert")
    expect(alert).toHaveClass("tinted-bad")
    expect(alert).toHaveTextContent("Analysis did not start")
    expect(within(alert).getAllByRole("listitem").map((r) => r.textContent)).toEqual([
      'requirements.txt:7numpy==2.1.3 ; platform_machine == "x86_64" or {x}marker has characters outside letters, digits, spaces and _.<>=!~"\'()-',
      "constraints.txtfile has more than 10000 lines",
    ])
    const replace = within(alert).getByRole("button", { name: "Replace files" })
    expect(within(alert).queryByRole("button", { name: "Retry" })).toBeNull()
    expect(screen.queryByRole("button", { name: /^Analyse$/ })).toBeNull()
    expect(alert.compareDocumentPosition(screen.getByText("See your administrators")) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()

    const chooser = container.querySelector('input[type="file"]') as HTMLInputElement
    const click = vi.spyOn(chooser, "click").mockImplementation(() => {})
    fireEvent.click(replace)
    expect(click).toHaveBeenCalledTimes(1)
  })

  it("keeps Retry for a start that fails otherwise", async () => {
    startProject = () => Promise.resolve(json({ type: "about:blank", title: "Service Unavailable", status: 503 }, 503))
    const { container } = withClient(<UpdateScreen from={pipProject.id} />)
    dropFiles(container, USUAL)
    fireEvent.click(await screen.findByRole("button", { name: /^Analyse$/ }))

    const alert = await screen.findByRole("alert")
    expect(alert).toHaveTextContent("No answer from this instance; your files are still here.")
    const retry = within(alert).getByRole("button", { name: "Retry" })
    expect(retry.parentElement?.lastElementChild).toBe(retry)

    startProject = () => Promise.resolve(json(createdPip, 201))
    fireEvent.click(retry)
    await waitFor(() => expect(navigate).toHaveBeenCalledWith({ to: "/crossings/$projectId", params: { projectId: createdPip.id } }))
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
