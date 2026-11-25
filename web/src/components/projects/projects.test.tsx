import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { createMemoryHistory, createRootRoute, createRoute, createRouter, Outlet, RouterProvider } from "@tanstack/react-router"
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react"
import type { ReactNode } from "react"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import type { Analysis, Export, Project, ProjectSummary } from "@/api/projects"
import { getInstance, getSigningKey, type Instance } from "@/api/settings"
import { ProjectPage } from "@/components/projects/project-page"
import { ProjectsList } from "@/components/projects/projects-list"
import { ONLINE_PLACES, onlineCrumbs } from "@/lib/places"
import { routeTree } from "@/routeTree.gen"

vi.mock("@/api/settings", async () => {
  const actual = await vi.importActual<typeof import("@/api/settings")>("@/api/settings")
  return { ...actual, getInstance: vi.fn(), getSigningKey: vi.fn() }
})

const SHA = "9c1e4b7a3f5d2c8e1a6b0d4f7c2e9a5b3d8f1c6e0a4b7d2f9c5e8a1b3d6f1a3b"
const CURRENT_KEY = `ef1bea90${"1".repeat(48)}b1673d46`
const OLD_KEY = `b7e3d1a9${"0".repeat(48)}36f4c218`
const FILES = ["findings.csv", "manifest.json", "manifest.json.sig", "packages_npm.tar.gz", "report.cdx.json", "report.trivy.json", "summary.md"]

const local = (month: number, day: number, hour = 10) => new Date(2026, month - 1, day, hour).toISOString()
const id = (at: string) => at.replace(/[-:]/g, "").replace(/\.\d+/, "")

function analysis(projectId: string, createdAt: string, state: Analysis["state"] = "done"): Analysis {
  return { id: id(createdAt), projectId, state, createdAt }
}

function exported(of: Analysis, state: Export["state"] = "done", files = FILES): Export {
  const at = new Date(new Date(of.createdAt).getTime() + 5 * 60_000).toISOString()
  return { id: id(at), projectId: of.projectId, analysisId: of.id, state, createdAt: at, files: state === "done" ? files : undefined }
}

function summary(name: string, ecosystem: "npm" | "pip", createdAt?: string, state: Analysis["state"] = "done", exportState?: Export["state"]): ProjectSummary {
  const last = createdAt ? analysis(name, createdAt, state) : undefined
  return { id: name, name, ecosystem, lastAnalysis: last, lastExport: last && exportState ? exported(last, exportState) : undefined }
}

const instance = (ephemeral: boolean): Instance =>
  ({ ephemeral, idleMinutes: 30, ready: true, preparing: [], brand: { name: "sealift", online: "Online", offline: "Offline", reviewWord: "PR", logo: false } }) as unknown as Instance

type Answer = () => Promise<Response>
const json = (body: unknown, status = 200): Answer => () => Promise.resolve(new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } }))
let files: Record<string, Answer> = {}
const fetchSpy = vi.fn((url: string) => {
  const name = decodeURIComponent(url.split("/files/")[1] ?? "")
  return (files[name] ?? json({ title: "Not Found", status: 404 }, 404))()
})

beforeEach(() => {
  vi.mocked(getInstance).mockResolvedValue(instance(false))
  vi.mocked(getSigningKey).mockResolvedValue({ publicKeyPem: "", publicKeySha256: CURRENT_KEY })
  files = {
    "manifest.json": json({ analysisId: "a", archive: { sha256: SHA, size: 4096 }, packages: [] }),
    "manifest.json.sig": json({ algorithm: "ed25519", publicKeySha256: CURRENT_KEY, signature: "c2ln" }),
    "summary.md": () => Promise.resolve(new Response("# Summary\n", { status: 200, headers: { "content-type": "application/octet-stream" } })),
  }
  fetchSpy.mockClear()
  vi.stubGlobal("fetch", fetchSpy)
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

async function renderIn(element: ReactNode) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const root = createRootRoute({ component: () => <Outlet /> })
  const page = (path: string, component = () => <p>page {path}</p>) => createRoute({ getParentRoute: () => root, path, component })
  const router = createRouter({
    routeTree: root.addChildren([page("/", () => <>{element}</>), page("/projects/$projectId"), page("/sessions/$sessionId"), page("/sessions/$sessionId/analysis")]),
    history: createMemoryHistory({ initialEntries: ["/"] }),
  })
  const view = render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  )
  await waitFor(() => expect(view.container.firstChild).not.toBeNull())
  return view
}

const rows = () => within(screen.getByRole("list", { name: "Projects" })).getAllByRole("link")

const NAMES = [
  "web-portal",
  "@acme/x",
  "analytics-ingest-pipeline-airflow-worker",
  "billing-api",
  "Reporting_Jobs",
  "plone.intranet",
  "@northwind-industries/holdings-dashboard",
]
const many = (n: number) =>
  Array.from({ length: n }, (_, i) => {
    const name = i < NAMES.length ? NAMES[i] : `${String.fromCharCode(97 + (i % 26))}-service-${i}`
    return summary(name, i % 3 === 0 ? "pip" : "npm", local(11, 1 + (i % 24), i % 20), "done", "done")
  })

describe("ProjectsList", () => {
  it("lists every project with its ecosystem, latest crossing day and state", async () => {
    await renderIn(
      <ProjectsList
        projects={[summary("web-portal", "npm", local(11, 23), "done", "done"), summary("ml-feature-store", "pip", local(11, 18), "running"), summary("legacy-cms", "npm")]}
      />,
    )
    expect(screen.getByRole("heading", { level: 1, name: "3 projects" })).toBeInTheDocument()
    const [first, second, third] = rows()
    expect(first).toHaveAttribute("href", "/projects/web-portal")
    expect(first).toHaveTextContent(/^web-portal\s*npm\s*23 Nov\s*Sealed$/)
    expect(second).toHaveTextContent(/^ml-feature-store\s*pip\s*18 Nov\s*Analysing$/)
    expect(third).toHaveTextContent(/^legacy-cms\s*npm\s*Not analysed yet$/)
  })

  it("writes the latest crossing's day alone in the list", async () => {
    await renderIn(<ProjectsList projects={[summary("web-portal", "npm", local(11, 23, 15), "done", "done")]} />)
    const [row] = rows()
    expect(within(row).getByText("23 Nov")).toHaveClass("figure")
    expect(row).not.toHaveTextContent("·")
  })

  it("draws a failed project as a closed red row", async () => {
    await renderIn(
      <ProjectsList projects={[summary("kiosk-ui", "npm", local(11, 19), "failed"), summary("etl-scheduler", "pip", local(11, 12), "done", "failed"), summary("docs-site", "npm", local(11, 14), "done", "done")]} />,
    )
    const row = (name: string) => rows().find((r) => r.getAttribute("href") === `/projects/${name}`) as HTMLElement
    const [analyse, seal, sealed] = [row("kiosk-ui"), row("etl-scheduler"), row("docs-site")]
    expect(analyse).toHaveClass("tinted-bad")
    expect(analyse).toHaveTextContent("Failed at Analyse")
    expect(seal).toHaveClass("tinted-bad")
    expect(seal).toHaveTextContent("Failed at Seal")
    expect(sealed).not.toHaveClass("tinted-bad")
  })

  it("offers Latest and Name only from two projects", async () => {
    const view = await renderIn(<ProjectsList projects={[summary("web-portal", "npm", local(11, 23))]} />)
    expect(screen.queryByRole("button", { name: "Latest" })).not.toBeInTheDocument()
    expect(screen.getByRole("heading", { level: 1, name: "1 project" })).toBeInTheDocument()
    view.unmount()
    await renderIn(<ProjectsList projects={[summary("web-portal", "npm", local(11, 23)), summary("billing-api", "npm", local(11, 21))]} />)
    expect(screen.getByRole("button", { name: "Latest" })).toHaveAttribute("aria-pressed", "true")
    expect(screen.getByRole("button", { name: "Name" })).toHaveAttribute("aria-pressed", "false")
  })

  it("shows 15 projects and a control that shows all 150 in Latest", async () => {
    await renderIn(<ProjectsList projects={many(150)} />)
    expect(rows()).toHaveLength(15)
    fireEvent.click(screen.getByRole("button", { name: "Show all 150 projects" }))
    expect(rows()).toHaveLength(150)
    expect(screen.queryByRole("button", { name: /^Show all/ })).not.toBeInTheDocument()
  })

  it("orders Latest newest first", async () => {
    await renderIn(<ProjectsList projects={[summary("old", "npm", local(10, 2)), summary("never", "npm"), summary("new", "npm", local(11, 20))]} />)
    expect(rows().map((r) => r.getAttribute("href"))).toEqual(["/projects/new", "/projects/old", "/projects/never"])
  })

  it("lists all 150 under their letters in Name with every name whole", async () => {
    const view = await renderIn(<ProjectsList projects={many(150)} />)
    fireEvent.click(screen.getByRole("button", { name: "Name" }))
    expect(screen.getByRole("button", { name: "Name" })).toHaveAttribute("aria-pressed", "true")
    expect(rows()).toHaveLength(150)
    const letters = screen.getAllByRole("heading", { level: 2 }).map((h) => h.textContent)
    expect(letters).toEqual([...letters].sort())
    expect(letters[0]).toBe("A")
    const underA = screen.getByRole("heading", { level: 2, name: "A" }).nextElementSibling as HTMLElement
    expect(within(underA).getAllByRole("link")[0]).toHaveTextContent(/^@acme\/x/)
    expect(within(screen.getByRole("heading", { level: 2, name: "N" }).nextElementSibling as HTMLElement).getByText("@northwind-industries/holdings-dashboard")).toBeInTheDocument()
    for (const name of NAMES) expect(screen.getByText(name)).toBeInTheDocument()
    expect(view.container.querySelectorAll(".truncate, .text-ellipsis, [class*='line-clamp']")).toHaveLength(0)
  })

  it("names an empty list in words and offers Update a project", async () => {
    await renderIn(<ProjectsList projects={[]} />)
    expect(screen.getByRole("heading", { level: 1, name: "No project yet" })).toBeInTheDocument()
    expect(screen.getByText("A project appears here after its first Update")).toBeInTheDocument()
    expect(screen.getByRole("link", { name: "Update a project" })).toHaveAttribute("href", "/")
    expect(screen.queryByRole("list", { name: "Projects" })).not.toBeInTheDocument()
  })

  it("shows the ephemeral line on Projects", async () => {
    vi.mocked(getInstance).mockResolvedValue(instance(true))
    await renderIn(<ProjectsList projects={[summary("web-portal", "npm", local(11, 23))]} />)
    expect(await screen.findByText("Ephemeral instance.")).toBeInTheDocument()
  })
})

function webPortal(): Project {
  const sealed = analysis("web-portal", local(11, 20, 9))
  const failed = analysis("web-portal", local(11, 20, 15), "failed")
  const cancelled = analysis("web-portal", local(11, 18), "cancelled")
  const earlier = analysis("web-portal", local(11, 6))
  return {
    id: "web-portal",
    name: "web-portal",
    ecosystem: "npm",
    target: { os: "linux", cpu: "x64", libc: "glibc", node: "22.17.1", pnpmVer: "10.34.5" },
    analyses: [cancelled, sealed, earlier, failed],
    exports: [exported(sealed), exported(earlier)],
  }
}

const crossing = (name: string) => screen.getByRole("heading", { level: 3, name }).closest("li") as HTMLElement

describe("ProjectPage", () => {
  it("lists a project's crossings newest first with their states", async () => {
    await renderIn(<ProjectPage project={webPortal()} />)
    expect(screen.getByRole("heading", { level: 1, name: "web-portal" })).toBeInTheDocument()
    expect(screen.getByRole("heading", { level: 2, name: "4 crossings" })).toBeInTheDocument()
    const items = within(screen.getByRole("list", { name: "Crossings" })).getAllByRole("heading", { level: 3 })
    expect(items.map((h) => h.textContent)).toEqual(["web-portal · 20 Nov · 2", "web-portal · 20 Nov", "web-portal · 18 Nov", "web-portal · 6 Nov"])
    expect(crossing("web-portal · 20 Nov · 2")).toHaveTextContent("Failed at Analyse")
    expect(crossing("web-portal · 20 Nov · 2").firstElementChild).toHaveClass("tinted-bad")
    expect(crossing("web-portal · 20 Nov")).toHaveTextContent("Sealed")
    expect(crossing("web-portal · 18 Nov")).toHaveTextContent("Cancelled")
  })

  it("opens each crossing on its own analysis", async () => {
    await renderIn(<ProjectPage project={webPortal()} />)
    for (const [name, at] of [
      ["web-portal · 18 Nov", local(11, 18)],
      ["web-portal · 20 Nov", local(11, 20, 9)],
    ]) {
      const open = within(crossing(name)).getByRole("link", { name: `Open ${name}` })
      expect(open).toHaveAttribute("href", `/sessions/web-portal/analysis?analysis=${id(at)}`)
    }
  })

  it("offers each To carry file for download by its full name and all three through Download all", async () => {
    const clicked: string[] = []
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
      clicked.push(`${this.getAttribute("href")} as ${this.getAttribute("download")}`)
    })
    await renderIn(<ProjectPage project={webPortal()} />)
    const open = crossing("web-portal · 20 Nov")
    expect(within(open).getByRole("button", { name: "7 files" })).toHaveAttribute("aria-expanded", "true")
    const carry = within(open).getByRole("region", { name: /^To carry/ })
    const base = `/api/projects/web-portal/exports/${exported(analysis("web-portal", local(11, 20, 9))).id}/files/`
    for (const name of ["packages_npm.tar.gz", "manifest.json", "manifest.json.sig"]) {
      expect(within(carry).getByText(name)).toBeInTheDocument()
      const link = within(carry).getByRole("link", { name: `Download ${name}` })
      expect(link).toHaveAttribute("href", base + name)
      expect(link).toHaveAttribute("download", name)
    }
    fireEvent.click(within(carry).getByRole("button", { name: "Download all" }))
    expect(clicked).toEqual(["packages_npm.tar.gz", "manifest.json", "manifest.json.sig"].map((name) => `${base}${name} as ${name}`))
  })

  it("opens a report first and offers its own download after", async () => {
    const opened = vi.fn()
    vi.stubGlobal("open", opened)
    const blobs: Blob[] = []
    URL.createObjectURL = vi.fn((blob: Blob) => {
      blobs.push(blob)
      return "blob:summary"
    })
    URL.revokeObjectURL = vi.fn()
    await renderIn(<ProjectPage project={webPortal()} />)
    const reports = within(crossing("web-portal · 20 Nov")).getByRole("region", { name: /^Reports/ })
    expect(within(reports).getAllByText(/\.(md|csv|json)$/).map((n) => n.textContent)).toEqual(["summary.md", "findings.csv", "report.cdx.json", "report.trivy.json"])
    const row = within(reports).getByText("summary.md").closest("li") as HTMLElement
    const controls = [...row.querySelectorAll<HTMLElement>("a, button")]
    expect(controls.map((c) => c.getAttribute("aria-label"))).toEqual(["Open summary.md", "Download summary.md"])
    expect(within(reports).queryByText("manifest.json")).not.toBeInTheDocument()
    fireEvent.click(controls[0])
    await waitFor(() => expect(opened).toHaveBeenCalledWith("blob:summary", "_blank"))
    expect(blobs[0].type).toBe("text/plain;charset=utf-8")
    expect(await blobs[0].text()).toBe("# Summary\n")
  })

  it("shows the archive's sha256 as a fingerprint", async () => {
    await renderIn(<ProjectPage project={webPortal()} />)
    const button = await screen.findByRole("button", { name: "sha256 of packages_npm.tar.gz 9c1e4b7a to 3d6f1a3b" })
    expect(button).toHaveAttribute("aria-expanded", "false")
    expect(screen.getByRole("button", { name: "Copy sha256 of packages_npm.tar.gz" })).toBeInTheDocument()
  })

  it("shows a reading row and keeps the downloads while the manifest is read", async () => {
    files["manifest.json"] = () => new Promise(() => {})
    await renderIn(<ProjectPage project={webPortal()} />)
    const reading = screen.getByText("Reading manifest.json").closest("[role=status]") as HTMLElement
    expect(reading).toHaveTextContent("Reading manifest.json")
    expect(reading).toHaveClass("tinted-info")
    const carry = screen.getByRole("region", { name: /^To carry/ })
    expect(within(carry).getAllByRole("link", { name: /^Download / })).toHaveLength(3)
    expect(within(carry).getByRole("button", { name: "Download all" })).toBeEnabled()
  })

  it("shows a closed red row with the cause and Retry when the manifest cannot be read", async () => {
    files["manifest.json"] = json({ title: "Not Found", status: 404, detail: "no file manifest.json in this export" }, 404)
    await renderIn(<ProjectPage project={webPortal()} />)
    const failure = await screen.findByText(/no file manifest\.json in this export/)
    const row = failure.closest(".tinted-bad") as HTMLElement
    expect(row).not.toBeNull()
    expect(row).toHaveTextContent("Could not read manifest.json")
    files["manifest.json"] = json({ analysisId: "a", archive: { sha256: SHA, size: 4096 }, packages: [] })
    fireEvent.click(within(row).getByRole("button", { name: "Retry" }))
    expect(await screen.findByRole("button", { name: /^sha256 of packages_npm\.tar\.gz/ })).toBeInTheDocument()
    expect(screen.getAllByRole("link", { name: /^Download / }).length).toBeGreaterThanOrEqual(3)
  })

  it("shows the replaced-key block only when the signature names another key", async () => {
    const view = await renderIn(<ProjectPage project={webPortal()} />)
    await screen.findByRole("button", { name: /^sha256 of packages_npm\.tar\.gz/ })
    expect(screen.queryByText("Signed with a key this instance has replaced")).not.toBeInTheDocument()
    view.unmount()

    files["manifest.json.sig"] = json({ algorithm: "ed25519", publicKeySha256: OLD_KEY, signature: "c2ln" })
    await renderIn(<ProjectPage project={webPortal()} />)
    const title = await screen.findByText("Signed with a key this instance has replaced")
    const block = title.closest(".tinted-warn") as HTMLElement
    expect(block).not.toBeNull()
    expect(block).toHaveTextContent("Offline refuses this archive unless it still trusts that key.")
    expect(within(block).getByRole("button", { name: "Key sha256 b7e3d1a9 to 36f4c218" })).toBeInTheDocument()
  })

  it("offers no Update or Add on a project", async () => {
    await renderIn(<ProjectPage project={webPortal()} />)
    expect(screen.queryByRole("button", { name: /^(Update|Add)\b/ })).not.toBeInTheDocument()
    expect(screen.queryByRole("link", { name: /^(Update|Add)\b/ })).not.toBeInTheDocument()
  })
})

describe("places and crumbs", () => {
  it("names a session's crumb by its crossing", () => {
    const project = webPortal()
    expect(onlineCrumbs("/sessions/web-portal/review", project)).toEqual([{ label: "Home", to: "/" }, { label: "web-portal · 20 Nov · 2" }])
    expect(onlineCrumbs("/sessions/web-portal/review", { ...project, analyses: [] })).toEqual([{ label: "Home", to: "/" }, { label: "web-portal" }])
    expect(onlineCrumbs("/projects")).toEqual([{ label: "Projects" }])
    expect(onlineCrumbs("/projects/web-portal", project)).toEqual([{ label: "Projects", to: "/projects" }, { label: "web-portal" }])
  })

  it("lists Home and Projects, both in the route tree", () => {
    expect(ONLINE_PLACES.map((p) => p.label)).toEqual(["Home", "Projects"])
    const paths = new Set(Object.keys(createRouter({ routeTree }).routesByPath))
    for (const place of ONLINE_PLACES) expect(paths).toContain(place.to)
    expect(paths).toContain("/projects/$projectId")
  })
})
