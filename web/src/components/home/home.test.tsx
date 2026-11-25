import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { fireEvent, render, screen, within } from "@testing-library/react"
import { RefreshCw } from "lucide-react"
import type { ReactNode } from "react"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import { apiFetch } from "@/api/client"
import type { Analysis, Export, Project, ProjectSummary } from "@/api/projects"
import { BrandProvider, DEFAULT_BRAND } from "@/components/frame/brand"
import { PathCard } from "@/components/home/blocks"
import { OnlineHome } from "@/components/home/online-home"
import { crossingDay } from "@/lib/crossings"

vi.mock("@/api/client", async () => {
  const actual = await vi.importActual<typeof import("@/api/client")>("@/api/client")
  return { ...actual, apiFetch: vi.fn() }
})
vi.mock("@tanstack/react-router", () => ({
  Link: ({ to, search, children, ...rest }: { to: string; search?: Record<string, string>; children: ReactNode }) => (
    <a href={search ? `${to}?${new URLSearchParams(search).toString()}` : to} {...rest}>
      {children}
    </a>
  ),
}))

const year = new Date().getFullYear()
// A local time this year, so a crossing's name carries no year.
const at = (month: number, day: number, hour = 10) => new Date(year, month, day, hour).toISOString()

const analysis = (project: string, state: Analysis["state"], createdAt: string, id = createdAt): Analysis => ({ id, projectId: project, state, createdAt })
const sealing = (project: string, analysisId: string, state: Export["state"], createdAt: string): Export => ({ id: `e-${createdAt}`, projectId: project, analysisId, state, createdAt })

function summary(name: string, last?: Analysis, exported?: Export): ProjectSummary {
  return { id: name, name, ecosystem: "npm", lastAnalysis: last, lastExport: exported }
}

let projects: ProjectSummary[] = []
let histories: Record<string, Analysis[]> = {}

function serve(rows: ProjectSummary[], history: Record<string, Analysis[]> = {}) {
  projects = rows
  histories = history
}

beforeEach(() => {
  serve([])
  vi.mocked(apiFetch).mockReset()
  vi.mocked(apiFetch).mockImplementation((path: string) => {
    if (path === "/projects") return Promise.resolve(projects) as never
    const id = /^\/projects\/([^/?]+)$/.exec(path)?.[1]
    const row = projects.find((p) => p.id === decodeURIComponent(id ?? ""))
    if (row) {
      const project: Project = { id: row.id, name: row.name, ecosystem: row.ecosystem, analyses: histories[row.id] ?? (row.lastAnalysis ? [row.lastAnalysis] : []) }
      return Promise.resolve(project) as never
    }
    return Promise.reject(new Error(`unexpected request ${path}`))
  })
})

afterEach(() => {
  document.documentElement.style.removeProperty("--brand-light")
  document.documentElement.style.removeProperty("--brand-dark")
})

function renderHome() {
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <OnlineHome />
    </QueryClientProvider>,
  )
}

const group = (name: string) => screen.getByRole("region", { name })
const rowNames = (region: HTMLElement) => within(region).getAllByRole("listitem").map((li) => li.querySelector("[data-row-name]")?.textContent)

describe("the online home", () => {
  it("shows one title and Update as the only path card, outlined as the lead", async () => {
    const { container } = renderHome()

    expect(await screen.findByRole("heading", { level: 1 })).toHaveTextContent("Start a crossing")
    expect(screen.getAllByRole("heading", { level: 1 })).toHaveLength(1)
    const cards = container.querySelectorAll("[data-path-card]")
    expect(cards).toHaveLength(1)
    const update = screen.getByRole("link", { name: "Update a project" })
    expect(update).toBe(cards[0])
    expect(update).toHaveAttribute("href", "/update")
    expect(update).toHaveClass("border-brand")
  })

  it("outlines the lead card with the accent where it reaches 3:1", () => {
    // Blue reads on the light page and falls under 3:1 on the dark one.
    render(
      <BrandProvider brand={{ ...DEFAULT_BRAND, accent: "#1d4ed8" }}>
        <PathCard to="/update" icon={RefreshCw} title="Update" detail="a project" lead />
        <PathCard to="/other" icon={RefreshCw} title="Other" detail="a path" />
      </BrandProvider>,
    )

    expect(screen.getByRole("link", { name: "Update a project" })).toHaveClass("border-brand")
    expect(screen.getByRole("link", { name: "Other a path" })).not.toHaveClass("border-brand")
    const root = document.documentElement.style
    expect(root.getPropertyValue("--brand-light")).toBe("#1d4ed8")
    expect(root.getPropertyValue("--brand-dark")).toBe("")
  })

  it("lists a review that waits, a failed analysis and a project not analysed yet in Needs you", async () => {
    serve([
      summary("web-portal", analysis("web-portal", "done", at(10, 23))),
      summary("kiosk-ui", analysis("kiosk-ui", "failed", at(10, 21))),
      summary("fresh"),
    ])
    renderHome()

    const needs = await screen.findByRole("region", { name: "Needs you" })
    expect(within(needs).getByText("Review waits")).toBeInTheDocument()
    expect(within(needs).getByText("Failed at Analyse")).toBeInTheDocument()
    expect(within(needs).getByText("Not analysed yet")).toBeInTheDocument()
    expect(within(needs).getByRole("link", { name: `Review web-portal · ${crossingDay(at(10, 23))}` })).toHaveAttribute("href", "/sessions/web-portal/review")
    expect(within(needs).getByRole("link", { name: `Open kiosk-ui · ${crossingDay(at(10, 21))}` })).toHaveAttribute("href", "/sessions/kiosk-ui")
    expect(within(needs).getByRole("link", { name: "Open fresh" })).toHaveAttribute("href", "/sessions/fresh/drop")
    expect(screen.queryByRole("region", { name: "In progress" })).toBeNull()
  })

  it("lists queued, analysing and sealing crossings in In progress", async () => {
    const done = analysis("data-pipeline", "done", at(10, 22))
    serve([
      summary("queued-one", analysis("queued-one", "queued", at(10, 24))),
      summary("billing-api", analysis("billing-api", "running", at(10, 23))),
      summary("data-pipeline", done, sealing("data-pipeline", done.id, "running", at(10, 22, 11))),
    ])
    renderHome()

    const progress = await screen.findByRole("region", { name: "In progress" })
    expect(within(progress).getByText("Queued")).toBeInTheDocument()
    expect(within(progress).getByText("Analysing")).toBeInTheDocument()
    expect(within(progress).getByText("Sealing")).toBeInTheDocument()
    expect(within(progress).getAllByRole("link", { name: /^Open / })).toHaveLength(3)
    expect(screen.queryByRole("region", { name: "Needs you" })).toBeNull()
  })

  it("lists a failed export in Needs you only, naming the step", async () => {
    const done = analysis("pdf-renderer", "done", at(10, 18))
    serve([
      summary("pdf-renderer", done, sealing("pdf-renderer", done.id, "failed", at(10, 18, 11))),
      summary("billing-api", analysis("billing-api", "running", at(10, 23))),
    ])
    renderHome()

    const needs = await screen.findByRole("region", { name: "Needs you" })
    expect(within(needs).getByText("Failed at Seal")).toBeInTheDocument()
    expect(within(needs).getByText(/^pdf-renderer/)).toBeInTheDocument()
    expect(within(group("In progress")).queryByText(/^pdf-renderer/)).toBeNull()
  })

  it("leaves sealed and cancelled crossings to Projects", async () => {
    const sealed = analysis("sealed-one", "done", at(10, 20))
    const exportedFirst = analysis("stopped-export", "done", at(10, 19))
    serve([
      summary("sealed-one", sealed, sealing("sealed-one", sealed.id, "done", at(10, 20, 11))),
      summary("stopped-analysis", analysis("stopped-analysis", "cancelled", at(10, 21))),
      summary("stopped-export", exportedFirst, sealing("stopped-export", exportedFirst.id, "cancelled", at(10, 19, 11))),
      summary("billing-api", analysis("billing-api", "running", at(10, 23))),
    ])
    renderHome()

    await screen.findByRole("region", { name: "In progress" })
    expect(screen.queryByText(/sealed-one|stopped-analysis|stopped-export/)).toBeNull()
    expect(screen.queryByRole("region", { name: "Needs you" })).toBeNull()
  })

  it("orders each group newest first", async () => {
    serve([
      summary("older", analysis("older", "done", at(10, 17))),
      summary("newest", analysis("newest", "failed", at(10, 23))),
      summary("middle", analysis("middle", "done", at(10, 20))),
      summary("run-old", analysis("run-old", "running", at(10, 2))),
      summary("run-new", analysis("run-new", "queued", at(10, 22))),
    ])
    renderHome()

    const needs = await screen.findByRole("region", { name: "Needs you" })
    expect(rowNames(needs).map((n) => n?.split(" · ")[0])).toEqual(["newest", "middle", "older"])
    expect(rowNames(group("In progress")).map((n) => n?.split(" · ")[0])).toEqual(["run-new", "run-old"])
  })

  it("names a second crossing of the same day with · 2", async () => {
    const second = analysis("web-portal", "done", at(10, 23, 15), "b")
    serve([summary("web-portal", second)], { "web-portal": [analysis("web-portal", "failed", at(10, 23, 9), "a"), second] })
    renderHome()

    expect(await screen.findByText(`web-portal · ${crossingDay(second.createdAt)} · 2`)).toBeInTheDocument()
  })

  it("hides an empty group", async () => {
    serve([summary("web-portal", analysis("web-portal", "done", at(10, 23)))])
    renderHome()

    await screen.findByRole("region", { name: "Needs you" })
    expect(screen.queryByRole("region", { name: "In progress" })).toBeNull()
    expect(screen.queryByText("No crossing in progress")).toBeNull()
  })

  it("names In progress in words when the instance holds no crossing", async () => {
    renderHome()

    const progress = await screen.findByRole("region", { name: "In progress" })
    expect(progress).toHaveTextContent("No crossing in progress")
    expect(screen.queryByRole("region", { name: "Needs you" })).toBeNull()
  })

  it("shows 10 rows of a group and a control that shows all 12", async () => {
    serve(Array.from({ length: 12 }, (_, i) => summary(`project-${i + 1}`, analysis(`project-${i + 1}`, "done", at(10, 24 - i)))))
    renderHome()

    const needs = await screen.findByRole("region", { name: "Needs you" })
    expect(within(needs).getAllByRole("listitem")).toHaveLength(10)
    fireEvent.click(within(needs).getByRole("button", { name: "Show all 12 crossings" }))
    expect(within(needs).getAllByRole("listitem")).toHaveLength(12)
    expect(within(needs).queryByRole("button", { name: /Show all/ })).toBeNull()
    expect(screen.getByRole("link", { name: `Review project-11 · ${crossingDay(at(10, 14))}` })).toHaveFocus()
  })

  it("draws a failed row as a closed red row", async () => {
    serve([
      summary("kiosk-ui", analysis("kiosk-ui", "failed", at(10, 21))),
      summary("web-portal", analysis("web-portal", "done", at(10, 23))),
    ])
    renderHome()

    const needs = await screen.findByRole("region", { name: "Needs you" })
    const [waits, failed] = within(needs).getAllByRole("listitem")
    expect(failed).toHaveTextContent("Failed at Analyse")
    expect(failed).toHaveClass("tinted-bad")
    expect(waits).not.toHaveClass("tinted-bad")
  })

  it("offers no Add, Hand-built, Find or Audit card", async () => {
    renderHome()

    await screen.findByRole("heading", { level: 1 })
    expect(screen.queryByRole("link", { name: /\b(Add|Hand-built|Find|Audit)\b/ })).toBeNull()
    expect(screen.queryByText(/\b(Add|Hand-built|Find in Nexus|Audit)\b/)).toBeNull()
  })
})
