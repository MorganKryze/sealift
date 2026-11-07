import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { act, render, screen, within } from "@testing-library/react"
import { createMemoryHistory, createRootRoute, createRoute, createRouter, RouterProvider } from "@tanstack/react-router"
import { afterEach, describe, expect, it, vi } from "vitest"

import type { Attempt, Import, ReportPackage } from "@/import/lib/outcome"

import { ImportsList } from "./imports-list"

afterEach(() => {
  vi.useRealTimers()
  vi.unstubAllGlobals()
})

const pkg = (state: string, over: Partial<ReportPackage> = {}): ReportPackage => ({
  name: "left-pad", version: "1.3.0", file: "npm/left-pad-1.3.0.tgz", state, reason: "", note: "", ...over,
})

const packages = (published: number, present: number, rest: ReportPackage[] = []) => [
  ...Array.from({ length: published }, () => pkg("published")),
  ...Array.from({ length: present }, () => pkg("present")),
  ...rest,
]

function attempt(n: number, outcome: string, pkgs: ReportPackage[], over: Partial<Attempt> = {}, reason = ""): Attempt {
  return {
    n, status: "ended", outcome,
    report: {
      outcome, reason, unencrypted: false, importVersion: "0.5.0",
      archive: { file: "", sha256: "", size: 0 }, toolVersion: "", analysisId: "",
      target: { os: "", cpu: "", libc: "", node: "", pnpmVer: "" }, nexus: { url: "", repository: "" },
      counts: { published: 0, present: 0, failed: 0 }, packages: pkgs,
    },
    ...over,
  }
}

function make(id: string, folder: string, outcome: string, attempts: Attempt[], createdAt: string): Import {
  return {
    id, createdAt, expectedSha256: "", outcome, archiveRemoved: false, attempts,
    archive: { key: `packages/npm/${folder}packages_npm.tar.gz`, etag: "\"a\"", size: 5_500_000 },
    manifest: { key: `packages/npm/${folder}manifest.json`, etag: "\"b\"", size: 900 },
  }
}

const queued = make("20261105T161200Z-0000a001", "2026-11-05-intranet-portal/", "queued", [attempt(1, "", [], { status: "queued" })], "2026-11-05T16:12:00Z")
const running = (done: number) =>
  make("20261105T153100Z-0000a002", "2026-11-05-billing-api/", "running", [
    attempt(1, "incomplete", packages(10, 0, [pkg("failed", { kind: "nexus", reason: "x" })])),
    attempt(2, "", packages(done, 0, Array.from({ length: 101 - done }, () => pkg("pending"))), { n: 2, status: "running" }),
  ], "2026-11-05T15:31:00Z")
const incomplete = make("20261103T142000Z-0000a003", "2026-11-03-kiosk-ui/", "incomplete", [
  attempt(1, "incomplete", packages(40, 58, [pkg("failed", { kind: "nexus", reason: "x" }), pkg("failed", { kind: "conflict", reason: "y" }), pkg("failed", { kind: "source", reason: "z" })])),
], "2026-11-03T14:20:00Z")
const interrupted = make("20261102T090500Z-0000a004", "2026-11-02-maps-viewer/", "interrupted", [
  attempt(1, "interrupted", packages(30, 4, [
    ...Array.from({ length: 40 }, () => pkg("failed", { kind: "interrupted", reason: "interrupted" })),
    ...Array.from({ length: 44 }, () => pkg("failed", { reason: "not reached" })),
  ])),
], "2026-11-02T09:05:00Z")
const refused = make("20261030T114000Z-0000a005", "2026-10-30-docs-site/", "refused", [
  attempt(1, "refused", [], {}, "the archive's sha256 is aaaa but the expected sha256 is bbbb. ".repeat(18)),
], "2026-10-30T11:40:00Z")
const complete = make("20261007T101500Z-0000a006", "2026-10-07-warehouse-scanner/", "complete", [
  attempt(1, "complete", packages(88, 17)),
], "2026-10-07T10:15:00Z")

const me = { user: "alice", minioConfigured: true, bucket: "user-alice", folder: "packages/npm/" }

function renderList(fetchImpl: () => Response | Promise<Response>) {
  vi.stubGlobal("fetch", vi.fn(async (url: string) => (url === "/api/me" ? json(me) : fetchImpl())))
  const root = createRootRoute({ component: ImportsList })
  const page = (p: string) => createRoute({ getParentRoute: () => root, path: p, component: () => <p>page {p}</p> })
  const router = createRouter({
    routeTree: root.addChildren([page("/"), page("/imports/$importId")]),
    history: createMemoryHistory({ initialEntries: ["/"] }),
  })
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={client}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  )
  return client
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": status < 400 ? "application/json" : "application/problem+json" } })

const rowOf = (name: string) => screen.getAllByRole("listitem").find((li) => li.textContent?.includes(name)) as HTMLElement

describe("ImportsList", () => {
  it("says the session has ended when a refresh meets the sign-in page", async () => {
    let ended = false
    const client = renderList(() => (ended ? new Response("<html>Sign in</html>", { status: 200, headers: { "Content-Type": "text/html" } }) : json({ imports: [complete] })))
    await screen.findAllByRole("listitem")
    ended = true
    await act(() => client.refetchQueries({ queryKey: ["imports"] }))
    expect(await screen.findByRole("heading", { name: "Your session has ended" })).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Sign in again" })).toBeInTheDocument()
    expect(screen.queryByRole("listitem")).not.toBeInTheDocument()
  })

  it("shows one row per import, newest first, with its words and counts", async () => {
    renderList(() => json({ imports: [complete, incomplete, queued, refused, running(37), interrupted] }))
    const rows = await screen.findAllByRole("listitem")
    expect(rows).toHaveLength(6)
    expect(rows.map((r) => within(r).getByRole("link").getAttribute("href"))).toEqual(
      [queued, running(37), incomplete, interrupted, refused, complete].map((i) => `/imports/${i.id}`),
    )

    const inc = within(rowOf("2026-11-03-kiosk-ui"))
    expect(inc.getByText("packages_npm.tar.gz")).toBeInTheDocument()
    expect(inc.getByText("2026-11-03-kiosk-ui/")).toBeInTheDocument()
    expect(inc.getByText("Incomplete")).toBeInTheDocument()
    expect(inc.getByText("Attempt 1")).toBeInTheDocument()
    expect(inc.getByText("40")).toBeInTheDocument()
    expect(inc.getByText("58")).toBeInTheDocument()
    expect(inc.getByText("3 packages not in Nexus. Open the import to retry.")).toBeInTheDocument()
    expect(inc.getByText(/Nov/)).toBeInTheDocument()

    const done = within(rowOf("2026-10-07-warehouse-scanner"))
    expect(done.getByText("Complete")).toBeInTheDocument()
    expect(done.getByText("88")).toBeInTheDocument()
    expect(done.getByText("17")).toBeInTheDocument()
    expect(done.queryByText(/not in Nexus/)).not.toBeInTheDocument()
  })

  it("counts packages not finished apart from failures on an interrupted row", async () => {
    renderList(() => json({ imports: [interrupted] }))
    const row = within(await screen.findByRole("listitem"))
    expect(row.getByText("Interrupted")).toBeInTheDocument()
    expect(row.getByText("84 packages not in Nexus. The service stopped before the attempt ended. Open the import to retry.")).toBeInTheDocument()
    expect(row.getByText("0", { selector: "b" })).toBeInTheDocument()
  })

  it("shows a refused import's reason cut to two lines and says nothing was published", async () => {
    renderList(() => json({ imports: [refused] }))
    const row = within(await screen.findByRole("listitem"))
    const reason = row.getByText(/the archive's sha256 is aaaa/)
    expect(reason.className).toContain("line-clamp-2")
    expect(row.getByText("Nothing was published. Start a new import from Archives.")).toBeInTheDocument()
    expect(row.queryByText(/published$/)).not.toBeInTheDocument()
  })

  it("has the row's link as its only control", async () => {
    renderList(() => json({ imports: [queued, running(37), incomplete, refused, complete] }))
    const rows = await screen.findAllByRole("listitem")
    for (const row of rows) {
      expect(within(row).getAllByRole("link")).toHaveLength(1)
      expect(within(row).queryAllByRole("button")).toHaveLength(0)
      expect(within(row).queryAllByRole("textbox")).toHaveLength(0)
    }
  })

  it("queued waits its turn", async () => {
    renderList(() => json({ imports: [queued] }))
    const row = within(await screen.findByRole("listitem"))
    expect(row.getByText("Queued")).toBeInTheDocument()
    expect(row.getByText("Waiting its turn")).toBeInTheDocument()
    expect(row.getByText("One import runs at a time for every user of the service, in the order they were started.")).toBeInTheDocument()
  })

  it("running row updates in place", async () => {
    let list = [running(37)]
    const client = renderList(() => json({ imports: list }))
    const row = within(await screen.findByRole("listitem"))
    expect(row.getByText("Running")).toBeInTheDocument()
    expect(row.getByText("37 of 101 packages")).toBeInTheDocument()
    const bar = row.getByRole("progressbar")
    const li = screen.getByRole("listitem")
    expect(bar).toHaveAttribute("aria-valuenow", "37")

    list = [running(61)]
    await act(() => client.refetchQueries({ queryKey: ["imports"] }))
    expect(await screen.findByText("61 of 101 packages")).toBeInTheDocument()
    expect(screen.getByRole("listitem")).toBe(li)
    expect(screen.getByRole("progressbar")).toBe(bar)
    expect(bar).toHaveAttribute("aria-valuenow", "60")
  })

  it("refetches every 5 seconds while an import runs and stops once none does", async () => {
    // The clock is faked before the first render so the query's timer is the fake one; it still ticks, so findBy works.
    vi.useFakeTimers({ shouldAdvanceTime: true })
    let list = [running(37)]
    renderList(() => json({ imports: list }))
    await screen.findByRole("listitem")
    const calls = () => (fetch as ReturnType<typeof vi.fn>).mock.calls.length
    const before = calls()

    await act(() => vi.advanceTimersByTimeAsync(5000))
    expect(calls()).toBe(before + 1)

    list = [complete]
    await act(() => vi.advanceTimersByTimeAsync(5000))
    expect(calls()).toBe(before + 2)
    await act(() => vi.advanceTimersByTimeAsync(30_000))
    expect(calls()).toBe(before + 2)
  })

  it("says what it reads while it loads, in one status region", async () => {
    renderList(() => new Promise<Response>(() => {}))
    expect(await screen.findByRole("status")).toHaveTextContent("Loading your imports")
    expect(screen.queryAllByRole("listitem")).toHaveLength(0)
    expect(screen.queryByRole("link", { name: /packages_npm/ })).not.toBeInTheDocument()
  })

  it("keeps the same status region from loading to the list", async () => {
    renderList(() => json({ imports: [queued, running(37), complete] }))
    const region = await screen.findByRole("status")
    await screen.findAllByRole("link", { name: /packages_npm/ })
    expect(screen.getByRole("status")).toBe(region)
    expect(region).toHaveTextContent("3 imports")
    expect(region).toHaveTextContent("1 running")
    expect(region).toHaveTextContent("1 queued")
  })

  it("no import yet says where an import starts and offers Choose an archive", async () => {
    renderList(() => json({ imports: [] }))
    expect(await screen.findByRole("heading", { name: "No import yet" })).toBeInTheDocument()
    expect(await screen.findByText("user-alice/packages/npm/")).toBeInTheDocument()
    expect(screen.getByText(/MinIO folder/)).toBeInTheDocument()
    expect(screen.getByRole("link", { name: "Choose an archive" })).toHaveAttribute("href", "/")
  })

  it("the list cannot be read gives the detail, Try again and says the archives are untouched", async () => {
    let fail = true
    const client = renderList(() =>
      fail ? json({ type: "about:blank", title: "Failed", status: 500, detail: "the data volume did not answer" }, 500) : json({ imports: [complete] }),
    )
    expect(await screen.findByText("the data volume did not answer")).toBeInTheDocument()
    expect(screen.getByText("Your archives in MinIO are untouched.")).toBeInTheDocument()
    fail = false
    await act(async () => screen.getByRole("button", { name: "Try again" }).click())
    expect(await screen.findByText("Complete")).toBeInTheDocument()
    expect(client.getQueryState(["imports"])?.status).toBe("success")
  })

  it("renders text from an archive as text", async () => {
    const odd = make("20261001T000000Z-0000a007", "<img src=x onerror=alert(1)>/", "refused", [
      attempt(1, "refused", [], {}, "<b>bold</b> javascript:alert(1)"),
    ], "2026-10-01T00:00:00Z")
    renderList(() => json({ imports: [odd] }))
    const row = await screen.findByRole("listitem")
    expect(row.querySelector("img")).toBeNull()
    expect(row.querySelector("b")).toBeNull()
    expect(within(row).getByText("<b>bold</b> javascript:alert(1)")).toBeInTheDocument()
  })
})
