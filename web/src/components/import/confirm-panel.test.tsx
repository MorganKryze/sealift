import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { createMemoryHistory, createRootRoute, Outlet, createRoute, createRouter, RouterProvider } from "@tanstack/react-router"
import { fireEvent, render, screen, waitFor } from "@testing-library/react"
import { afterEach, describe, expect, it, vi } from "vitest"

import type { Archive } from "@/import/api/queries"
import type { Import } from "@/import/lib/outcome"

import { ArchiveRow } from "./archive-row"
import { ConfirmPanel } from "./confirm-panel"

afterEach(() => {
  vi.unstubAllGlobals()
})

const KEY = "packages/npm/2026-11-05-reports/packages_npm.tar.gz"
const NAME = "2026-11-05-reports/packages_npm.tar.gz"
const archive: Archive = { key: KEY, size: 5_500_000, modified: "2026-11-05T08:00:00Z", importable: true }
const DIGEST = "a".repeat(64)

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": status < 400 ? "application/json" : "application/problem+json" } })
const problem = (status: number, title: string, detail?: string, importId?: string) => json({ type: "about:blank", title, status, detail, importId }, status)

const own = (outcome: string): Import =>
  ({ id: "20261106T093000Z-a1000001", outcome, createdAt: "2026-11-06T09:30:00Z", expectedSha256: "", archiveRemoved: false, attempts: [], archive: { key: "packages/npm/2026-11-06-other/packages_npm.tar.gz", etag: "\"a\"", size: 1 }, manifest: { key: "m", etag: "\"b\"", size: 1 } }) as Import

function renderPanel(answer: (url: string, init?: RequestInit) => Response | Promise<Response> = () => json({}), ownActive?: Import, onClose: () => void = () => {}) {
  const fetchMock = vi.fn(async (url: string, init?: RequestInit) => (url === "/api/archives" || url === "/api/imports") && !init ? json(url === "/api/imports" ? { imports: [] } : { archives: [] }) : answer(url, init))
  vi.stubGlobal("fetch", fetchMock)
  const root = createRootRoute({ component: () => <><ConfirmPanel archive={archive} ownActive={ownActive} onClose={onClose} /><Outlet /></> })
  const page = createRoute({ getParentRoute: () => root, path: "/imports/$importId", component: () => <p>import page</p> })
  const router = createRouter({ routeTree: root.addChildren([page]), history: createMemoryHistory({ initialEntries: ["/"] }) })
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><RouterProvider router={router} /></QueryClientProvider>)
  return { fetchMock, router }
}

const posts = (fetchMock: ReturnType<typeof vi.fn>) => fetchMock.mock.calls.filter((c) => (c[1] as RequestInit | undefined)?.method === "POST")
const field = () => screen.findByLabelText(/Expected sha256/)
const startButton = () => screen.getByRole("button", { name: "Start the import" })

describe("ConfirmPanel", () => {
  it("says what the import does", async () => {
    renderPanel()
    const input = await field()
    expect(input).toHaveFocus()
    expect(screen.getByText(/reads the archive and its manifest.json, checks the archive's sha256, publishes each package to Nexus/)).toBeInTheDocument()
    expect(screen.getByText(/removes nothing from MinIO until every package is in Nexus/)).toBeInTheDocument()
    expect(screen.getByText(/Imports run one at a time for every user/)).toBeInTheDocument()
    expect(screen.getByText("Expected sha256 (optional)")).toBeInTheDocument()
  })

  it("names your own import", async () => {
    renderPanel(undefined, own("running"))
    expect(await screen.findByText(/Your import of 2026-11-06-other\/packages_npm.tar.gz is running/)).toBeInTheDocument()
    expect(screen.queryByText(/for every user/)).not.toBeInTheDocument()
  })

  it("names your own queued import", async () => {
    renderPanel(undefined, own("queued"))
    expect(await screen.findByText(/Your import of 2026-11-06-other\/packages_npm.tar.gz is queued/)).toBeInTheDocument()
  })

  it.each([
    ["63 digits", "a".repeat(63)],
    ["a g", `${"a".repeat(63)}g`],
    ["spaces inside", `${"a".repeat(32)} ${"a".repeat(32)}`],
  ])("a malformed sha256 sends nothing: %s", async (_name, value) => {
    const { fetchMock } = renderPanel()
    fireEvent.change(await field(), { target: { value } })
    fireEvent.click(startButton())
    expect(await screen.findByText("The sha256 is 64 hexadecimal digits, 0 to 9 and a to f. Check the value you copied, or leave the field empty.")).toBeInTheDocument()
    expect(screen.getByLabelText(/Expected sha256/)).toHaveAttribute("aria-invalid", "true")
    expect(posts(fetchMock)).toHaveLength(0)
  })

  it("the panel's own button starts, and Start on the row only opens the panel", async () => {
    const root = createRootRoute({ component: () => <ul><ArchiveRow archive={archive} /></ul> })
    const router = createRouter({ routeTree: root, history: createMemoryHistory({ initialEntries: ["/"] }) })
    const fetchMock = vi.fn(async () => json({}))
    vi.stubGlobal("fetch", fetchMock)
    render(<QueryClientProvider client={new QueryClient()}><RouterProvider router={router} /></QueryClientProvider>)
    fireEvent.click(await screen.findByRole("button", { name: `Start import of ${NAME}` }))
    expect(await screen.findByRole("region", { name: `Start the import of ${NAME}` })).toBeInTheDocument()
    expect(posts(fetchMock)).toHaveLength(0)
  })

  it("Escape and Cancel return focus to the row's Start", async () => {
    for (const close of [
      () => fireEvent.keyDown(screen.getByLabelText(/Expected sha256/), { key: "Escape" }),
      () => fireEvent.click(screen.getByRole("button", { name: "Cancel" })),
    ]) {
      const root = createRootRoute({ component: () => <ul><ArchiveRow archive={archive} /></ul> })
      const router = createRouter({ routeTree: root, history: createMemoryHistory({ initialEntries: ["/"] }) })
      const view = render(<QueryClientProvider client={new QueryClient()}><RouterProvider router={router} /></QueryClientProvider>)
      const start = await screen.findByRole("button", { name: `Start import of ${NAME}` })
      fireEvent.click(start)
      expect(await field()).toHaveFocus()
      close()
      await waitFor(() => expect(screen.queryByRole("region")).not.toBeInTheDocument())
      expect(start).toHaveFocus()
      view.unmount()
    }
  })

  it("202 opens the import and sends the JSON the service requires", async () => {
    const { fetchMock, router } = renderPanel((url) => (url === "/api/imports" ? json({ id: "20261106T100000Z-b0000001" }, 202) : json({})))
    fireEvent.change(await field(), { target: { value: ` ${DIGEST} ` } })
    fireEvent.click(startButton())
    await screen.findByText("import page")
    expect(router.state.location.pathname).toBe("/imports/20261106T100000Z-b0000001")
    const [, init] = posts(fetchMock)[0] as [string, RequestInit]
    expect(init.headers).toEqual({ "Content-Type": "application/json" })
    expect(JSON.parse(init.body as string)).toEqual({ archive: KEY, expectedSha256: DIGEST })
  })

  it("sends no expected sha256 when the field is empty", async () => {
    const { fetchMock } = renderPanel(() => json({ id: "20261106T100000Z-b0000001" }, 202))
    await field()
    fireEvent.click(startButton())
    await screen.findByText("import page")
    expect(JSON.parse((posts(fetchMock)[0][1] as RequestInit).body as string)).toEqual({ archive: KEY })
  })

  it("409 with an id says the import has not completed and links to it", async () => {
    renderPanel(() => problem(409, "Conflict", "already imported", "20261105T090000Z-0000a001"))
    await field()
    fireEvent.click(startButton())
    expect(await screen.findByText("This archive has an import that has not completed.")).toBeInTheDocument()
    expect(screen.getByRole("link", { name: "Open that import" })).toHaveAttribute("href", "/imports/20261105T090000Z-0000a001")
  })

  it.each([["no id", undefined], ["an empty id", ""]])("409 with %s shows the detail", async (_name, importId) => {
    renderPanel(() => problem(409, "Conflict", "MinIO is not configured", importId))
    await field()
    fireEvent.click(startButton())
    expect(await screen.findByText("MinIO is not configured")).toBeInTheDocument()
    expect(screen.queryByRole("link")).not.toBeInTheDocument()
  })

  it("404 says the archive is no longer in the folder and offers Refresh", async () => {
    const { fetchMock } = renderPanel((_url, init) => (init?.method === "POST" ? problem(404, "Not found", "no such archive") : json({ imports: [], archives: [] })))
    await field()
    fireEvent.click(startButton())
    expect(await screen.findByText("This archive is no longer in your folder.")).toBeInTheDocument()
    const before = fetchMock.mock.calls.filter((c) => c[0] === "/api/archives").length
    fireEvent.click(screen.getByRole("button", { name: "Refresh" }))
    await waitFor(() => expect(fetchMock.mock.calls.filter((c) => c[0] === "/api/archives").length).toBe(before + 1))
  })

  it("502 shows the import failure with the cause", async () => {
    renderPanel(() => problem(502, "Bad Gateway", "MinIO refused the read"))
    await field()
    fireEvent.click(startButton())
    expect(await screen.findByText("The import could not be started")).toBeInTheDocument()
    expect(screen.getByText("MinIO refused the read")).toBeInTheDocument()
    expect(screen.getByText("502 Bad Gateway")).toBeInTheDocument()
  })
})
