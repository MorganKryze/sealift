import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { act, render, screen, within } from "@testing-library/react"
import { createMemoryHistory, createRouter, RouterProvider } from "@tanstack/react-router"
import { afterEach, beforeEach, expect, it, vi } from "vitest"

import type { Attempt, Import, ReportPackage } from "@/import/lib/outcome"
import { routeTree } from "@/import/routeTree.gen"

const ID = "20261125T142000Z-a2000001"
const KEY = "packages/npm/web-portal-2026-11-25/packages_npm.tar.gz"

const pkg = (i: number, state: string): ReportPackage => ({
  name: `package-${i}`, version: "1.0.0", file: `npm/package-${i}/-/package-${i}-1.0.0.tgz`, state, reason: "", note: "",
})

function attempt(n: number, checked: boolean, published = 0): Attempt {
  const packages = [0, 1, 2, 3].map((i) => pkg(i, i < published ? "published" : "pending"))
  return {
    n, status: "running", outcome: "",
    report: {
      outcome: "", reason: "", unencrypted: false, importVersion: "", archive: { file: "packages_npm.tar.gz", sha256: "", size: 0 }, toolVersion: "", analysisId: "",
      target: { os: "", cpu: "", libc: "", node: "", pnpmVer: "" }, nexus: { url: "", repository: "" },
      counts: { published, present: 0, failed: 0 }, packages, archiveChecked: checked,
      crossing: { project: "web-portal", sealedAt: "2026-11-25T08:00:00Z", packages: 4 },
    },
  }
}

const make = (attempts: Attempt[]): Import => ({
  id: ID, createdAt: new Date(2026, 10, 25, 14, 20).toISOString(), expectedSha256: "", outcome: "running", archiveRemoved: false, attempts,
  archive: { key: KEY, etag: '"a"', size: 101_187_584 }, manifest: { key: "packages/npm/web-portal-2026-11-25/manifest.json", etag: '"b"', size: 1 },
})

let current: Import

beforeEach(() => {
  vi.stubGlobal("fetch", vi.fn(async (url: string) => {
    const body = url.endsWith("/me") ? { user: "alice", publicKeySha256: "" } : current
    return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } })
  }))
})

afterEach(() => {
  vi.unstubAllGlobals()
})

/** Renders the import's page through the screens' own routes, its data already read. */
async function openPage(first: Import) {
  current = first
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } })
  client.setQueryData(["imports", ID], first)
  const router = createRouter({ routeTree, history: createMemoryHistory({ initialEntries: [`/imports/${ID}`] }) })
  render(
    <QueryClientProvider client={client}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  )
  await screen.findByRole("heading", { level: 1 })
  // The query client tells its observers on the next tick, so the poll waits for it.
  const poll = async (next: Import) => {
    current = next
    await act(async () => {
      client.setQueryData(["imports", ID], next)
      await new Promise((resolve) => setTimeout(resolve, 0))
    })
  }
  return { poll }
}

it("names the import in the breadcrumb by its crossing", async () => {
  await openPage(make([attempt(1, false)]))
  const crumbs = screen.getByRole("navigation", { name: "Breadcrumb" })
  expect(within(crumbs).getByRole("link", { name: "Imports" })).toBeInTheDocument()
  expect(crumbs).toHaveTextContent("web-portal · 25 Nov")
  expect(crumbs).not.toHaveTextContent(/Import$/)
})

it("keeps the progress node while one attempt moves from its checks to publishing", async () => {
  const { poll } = await openPage(make([attempt(1, false)]))
  const before = screen.getByRole("heading", { level: 1 })
  await poll(make([attempt(1, true, 1)]))
  expect(document.body).toHaveTextContent("1 of 4 packages in Nexus")
  expect(screen.getByRole("heading", { level: 1 })).toBe(before)
})

it("draws a new progress node when a new attempt starts", async () => {
  const { poll } = await openPage(make([attempt(1, true, 1)]))
  const before = screen.getByRole("heading", { level: 1 })
  await poll(make([{ ...attempt(1, true, 1), status: "ended", outcome: "incomplete" }, attempt(2, true, 2)]))
  expect(document.body).toHaveTextContent("2 of 4 packages in Nexus")
  expect(screen.getByRole("heading", { level: 1 })).not.toBe(before)
})
