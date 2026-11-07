import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react"
import { createMemoryHistory, createRootRoute, createRoute, createRouter, RouterProvider } from "@tanstack/react-router"
import { afterEach, describe, expect, it, vi } from "vitest"

import type { Archive, ArchiveList } from "@/import/api/queries"

import { ArchivesList } from "./archives-list"

afterEach(() => {
  vi.unstubAllGlobals()
})

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": status < 400 ? "application/json" : "application/problem+json" } })

const me = { user: "alice", minioConfigured: true, bucket: "user-alice", folder: "packages/npm/" }

const archive = (folder: string, modified: string, over: Partial<Archive> = {}): Archive => ({
  key: `packages/npm/${folder}packages_npm.tar.gz`, size: 5_500_000, modified, importable: true, ...over,
})

const folderList = (archives: Archive[], over: Partial<ArchiveList> = {}): ArchiveList => ({
  minioConfigured: true, bucket: "user-alice", folder: "packages/npm/", bucketMissing: false, truncated: false, unencrypted: [], archives, ...over,
})

function renderList(answer: () => Response | Promise<Response>, seed?: (client: QueryClient) => void) {
  const fetchMock = vi.fn(async (url: string) => {
    if (url === "/api/me") return json(me)
    if (url === "/api/imports") return json({ imports: [] })
    return answer()
  })
  vi.stubGlobal("fetch", fetchMock)
  const root = createRootRoute({ component: ArchivesList })
  const page = (p: string) => createRoute({ getParentRoute: () => root, path: p, component: () => <p>page {p}</p> })
  const router = createRouter({
    routeTree: root.addChildren([page("/imports/$importId")]),
    history: createMemoryHistory({ initialEntries: ["/"] }),
  })
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  seed?.(client)
  render(
    <QueryClientProvider client={client}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  )
  return fetchMock
}

const three = [
  archive("2026-11-02-old/", "2026-11-02T09:00:00Z"),
  archive("2026-11-06-new/", "2026-11-06T09:00:00Z"),
  archive("2026-11-04-bad/", "2026-11-04T09:00:00Z", { importable: false, reason: "no manifest.json in its folder" }),
]

describe("ArchivesList", () => {
  it("reads the folder again when the screen opens, so a row shows the import started since", async () => {
    const before = folderList([archive("lab/", "2026-11-06T09:00:00Z")])
    const after = folderList([archive("lab/", "2026-11-06T09:00:00Z", { latestImport: { id: "i1", outcome: "refused" } })])
    renderList(
      () => json(after),
      (client) => client.setQueryData(["archives"], before),
    )
    expect(await screen.findByText("Refused")).toBeInTheDocument()
    expect(screen.queryByText("Not imported yet")).not.toBeInTheDocument()
  })

  it("lists every archive newest first", async () => {
    renderList(() => json(folderList([...three].sort((a, b) => a.key.localeCompare(b.key)))))
    const rows = await screen.findAllByRole("listitem")
    expect(rows.map((r) => within(r).getByText(/^20\d\d-11-\d\d-/).textContent)).toEqual(["2026-11-06-new/", "2026-11-04-bad/", "2026-11-02-old/"])
    const first = within(rows[0])
    expect(first.getByText("packages_npm.tar.gz")).toBeInTheDocument()
    expect(first.getByText("5.2 MB")).toBeInTheDocument()
    expect(first.getByText(/Nov/)).toBeInTheDocument()
    expect(first.getByText("Can be imported")).toBeInTheDocument()
    expect(within(rows[1]).getByText("Cannot be imported")).toBeInTheDocument()
    expect(screen.getByRole("status")).toHaveTextContent("3 archives · 2 importable")
  })

  it("says where to upload when the folder is empty", async () => {
    renderList(() => json(folderList([])))
    expect(await screen.findByRole("heading", { name: "No archive in your folder" })).toBeInTheDocument()
    expect(screen.getByText("manifest.json")).toBeInTheDocument()
    expect(screen.getByText("user-alice/packages/npm/")).toBeInTheDocument()
    expect(screen.getByText(/side by side/)).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Refresh" })).toBeInTheDocument()
  })

  it("gives the API's message when the bucket is missing", async () => {
    renderList(() => json(folderList([], { bucketMissing: true, message: "MinIO has no bucket user-alice yet: nothing to list" })))
    expect(await screen.findByText(/MinIO has no bucket user-alice yet: nothing to list/)).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Refresh" })).toBeInTheDocument()
  })

  it("says MinIO is not configured and who sets it", async () => {
    renderList(() => json(folderList([], { minioConfigured: false })))
    expect(await screen.findByRole("heading", { name: "MinIO is not configured" })).toBeInTheDocument()
    expect(screen.getByText(/The administrator sets it in the settings file/)).toBeInTheDocument()
  })

  it("names the user's folder in the status region while it loads and keeps the list's height", async () => {
    renderList(() => new Promise<Response>(() => {}))
    const status = await screen.findByRole("status")
    await waitFor(() => expect(status).toHaveTextContent("Reading your folder in MinIO: user-alice/packages/npm/"))
    expect(document.querySelectorAll("[aria-hidden] > .min-h-18")).toHaveLength(4)
    expect(screen.queryByRole("listitem")).not.toBeInTheDocument()
  })

  it("shows MinIO's reason on a 502 with the next action and a folded detail", async () => {
    const fetchMock = renderList(() => json({ type: "about:blank", title: "MinIO failed", status: 502, detail: "MinIO could not list the archives: connection refused" }, 502))
    const alert = await screen.findByRole("alert")
    expect(within(alert).getByText("MinIO could not list the archives: connection refused")).toBeInTheDocument()
    expect(within(alert).getByText(/Imports already started go on/)).toBeInTheDocument()
    const detail = within(alert).getByText("502 MinIO failed")
    expect(detail.closest("details")).not.toHaveAttribute("open")
    fireEvent.click(within(alert).getByRole("button", { name: "Try again" }))
    await waitFor(() => expect(fetchMock.mock.calls.filter(([u]) => u === "/api/archives")).toHaveLength(2))
  })

  it("says the list is cut and how to make room", async () => {
    renderList(() => json(folderList(three, { truncated: true })))
    await screen.findAllByRole("listitem")
    expect(screen.getByText(/the first 1,000 in name order, so a newer archive may be missing/)).toBeInTheDocument()
    expect(screen.getByText(/Moving finished archives out of packages\/npm\/ makes room/)).toBeInTheDocument()
  })

  it("filters All and Importable as a two-choice control without pagination", async () => {
    renderList(() => json(folderList(three)))
    await screen.findAllByRole("listitem")
    const all = screen.getByRole("button", { name: "All 3" })
    const importable = screen.getByRole("button", { name: "Importable 2" })
    expect(all).toHaveAttribute("aria-pressed", "true")
    expect(screen.getAllByRole("group")).toHaveLength(1)
    fireEvent.click(importable)
    expect(importable).toHaveAttribute("aria-pressed", "true")
    expect(screen.getAllByRole("listitem")).toHaveLength(2)
    expect(screen.queryByText("Cannot be imported")).not.toBeInTheDocument()
    expect(screen.queryByRole("navigation")).not.toBeInTheDocument()
  })

  it("keeps the filter when no archive can be imported", async () => {
    renderList(() => json(folderList([three[2]])))
    fireEvent.click(await screen.findByRole("button", { name: "Importable 0" }))
    expect(screen.getByText(/No archive can be imported/)).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "All 1" })).toBeInTheDocument()
  })

  it("names each plain http link and says contents and credentials cross unencrypted", async () => {
    renderList(() => json(folderList(three, { unencrypted: ["keySet", "minio", "nexus"] })))
    await screen.findAllByRole("listitem")
    expect(screen.getByText(/The links to the key set, MinIO and Nexus run over plain http/)).toBeInTheDocument()
    expect(screen.getByText(/Package contents and credentials cross the network unencrypted/)).toBeInTheDocument()
  })

  it("shows no notice for an encrypted, complete list", async () => {
    renderList(() => json(folderList(three)))
    await screen.findAllByRole("listitem")
    expect(screen.queryByText(/plain http/)).not.toBeInTheDocument()
    expect(screen.queryByText(/first 1,000/)).not.toBeInTheDocument()
  })
})
