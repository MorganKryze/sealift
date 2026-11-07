import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { createMemoryHistory, createRootRoute, createRoute, createRouter, RouterProvider } from "@tanstack/react-router"
import { render, screen, within } from "@testing-library/react"
import { afterEach, describe, expect, it, vi } from "vitest"

import { importPollInterval } from "@/import/api/queries"
import type { Attempt, Import, ReportPackage } from "@/import/lib/outcome"

import { EndState } from "./end-state"

afterEach(() => {
  vi.unstubAllGlobals()
})

const pkg = (state: string, over: Partial<ReportPackage> = {}): ReportPackage => ({
  name: "left-pad", version: "1.3.0", file: "x", state, reason: "", note: "", ...over,
})
const many = (n: number, state: string, over: Partial<ReportPackage> = {}) => Array.from({ length: n }, () => pkg(state, over))

function attempt(outcome: string, packages: ReportPackage[], over: Partial<Attempt> = {}, reason = ""): Attempt {
  return {
    n: 1, status: "ended", outcome, endedAt: "2026-11-05T15:47:00Z",
    report: {
      outcome, reason, unencrypted: false, importVersion: "0.5.0", archive: { file: "", sha256: "", size: 0 }, toolVersion: "", analysisId: "",
      target: { os: "", cpu: "", libc: "", node: "", pnpmVer: "" }, nexus: { url: "", repository: "" },
      counts: { published: 0, present: 0, failed: 0 }, packages, archiveChecked: true,
    },
    ...over,
  }
}

const ARCHIVE_ETAG = "\"7c1d0a5e9b3f48d2a6e1c04b5f7a93d2-52\""
const MANIFEST_ETAG = "\"e41b6d0c97a2358f1c6b0d94a7e35f82\""

function make(a: Attempt, over: Partial<Import> = {}): Import {
  return {
    id: "20261105T161200Z-a1000003", createdAt: "2026-11-05T16:12:00Z", expectedSha256: "", outcome: a.outcome, archiveRemoved: false, attempts: [a],
    archive: { key: "packages/npm/2026-11-05-hr-forms/packages_npm.tar.gz", etag: ARCHIVE_ETAG, size: 5_500_000 },
    manifest: { key: "packages/npm/2026-11-05-hr-forms/manifest.json", etag: MANIFEST_ETAG, size: 900 },
    ...over,
  }
}

function renderEnd(imp: Import) {
  vi.stubGlobal("fetch", vi.fn(async () => new Response("{}", { status: 200, headers: { "Content-Type": "application/json" } })))
  const root = createRootRoute({ component: () => <><p>page</p><EndState imp={imp} /></> })
  const archives = createRoute({ getParentRoute: () => root, path: "/archives", component: () => null })
  const router = createRouter({ routeTree: root.addChildren([archives]), history: createMemoryHistory({ initialEntries: ["/"] }) })
  return render(<QueryClientProvider client={new QueryClient()}><RouterProvider router={router} /></QueryClientProvider>)
}

describe("EndState", () => {
  it("complete, removed: says every package is in Nexus, both objects went after their ETag check, and shows both ETags", async () => {
    const a = attempt("complete", [...many(94, "published"), ...many(7, "present")], { removal: { removed: true, reason: "" } })
    renderEnd(make(a, { archiveRemoved: true }))
    expect(await screen.findByRole("heading", { name: "Archive removed from MinIO" })).toBeInTheDocument()
    expect(screen.getByText(/All 101 packages are in Nexus: 94 published, 7 present\./)).toBeInTheDocument()
    expect(screen.getByText(/removed both objects from your folder, after checking that each still carried the ETag it read/)).toBeInTheDocument()
    expect(screen.getByText(ARCHIVE_ETAG)).toBeInTheDocument()
    expect(screen.getByText(MANIFEST_ETAG)).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Copy archive ETag" })).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Copy manifest ETag" })).toBeInTheDocument()
    expect(screen.queryByRole("button", { name: "Retry import" })).toBeNull()
  })

  it("complete, removed: shows the reason when the manifest could not be removed", async () => {
    const reason = "the archive was removed, but the manifest could not be and stays in the folder: access denied"
    const a = attempt("complete", many(3, "published"), { removal: { removed: true, reason } })
    renderEnd(make(a, { archiveRemoved: true }))
    expect(await screen.findByText(reason)).toBeInTheDocument()
    expect(screen.queryByText(/removed both objects/)).toBeNull()
    expect(screen.getByRole("heading", { name: "Archive removed from MinIO, manifest kept" })).toBeInTheDocument()
  })

  it("complete, kept: says the archive stays, gives the recorded reason and offers Retry with what it does", async () => {
    const reason = "the archive's ETag changed after the import read it"
    const a = attempt("complete", [...many(50, "published"), ...many(10, "present")], { removal: { removed: false, reason } })
    renderEnd(make(a))
    expect(await screen.findByRole("heading", { name: "Archive kept in MinIO" })).toBeInTheDocument()
    expect(screen.getByText(/All 60 packages are in Nexus/)).toBeInTheDocument()
    expect(screen.getByText(reason)).toBeInTheDocument()
    expect(screen.getByText(/it checks every package again and removes the archive only if both objects still carry the ETags this import read/)).toBeInTheDocument()
    expect(screen.getByText(/An archive replaced since is refused/)).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Retry import" })).toBeInTheDocument()
  })

  it("removal being checked: says so, never says removed, and the page keeps polling", async () => {
    const a = attempt("complete", many(40, "published"))
    const imp = make(a)
    renderEnd(imp)
    expect(await screen.findByText(/The archive's removal is being checked/)).toBeInTheDocument()
    expect(screen.getByText(/All 40 packages are in Nexus/)).toBeInTheDocument()
    expect(document.body.textContent ?? "").not.toMatch(/removed/i)
    expect(screen.queryByRole("button", { name: "Retry import" })).toBeNull()
    expect(importPollInterval(imp)).toBe(2000)
  })

  it("refused: gives the reason in full, both digests, nothing published, no package read, one action and no Retry", async () => {
    const computed = "c".repeat(64)
    const expected = "e".repeat(64)
    const reason = `the archive's sha256 is ${computed} but the expected sha256 is ${expected}`
    const a = attempt("refused", [], { report: { ...attempt("refused", [], {}, reason).report, archiveChecked: false } })
    renderEnd(make(a, { expectedSha256: expected }))
    expect(await screen.findByRole("heading", { name: "Refused before the first package" })).toBeInTheDocument()
    const cause = screen.getByText(reason)
    expect(cause).toHaveTextContent(computed)
    expect(cause).toHaveTextContent(expected)
    expect(screen.getByText(/Nothing was published/)).toBeInTheDocument()
    expect(screen.getByText(/No package was read/)).toBeInTheDocument()
    expect(screen.getByRole("link", { name: "Go to archives" })).toHaveAttribute("href", "/")
    expect(screen.queryByRole("button", { name: "Retry import" })).toBeNull()
  })

  it("refused: tints the panel red, as the refusal is the one end state that stops everything", async () => {
    const a = attempt("refused", [], { report: { ...attempt("refused", [], {}, "the archive's sha256 is x but the expected sha256 is y").report, archiveChecked: false } })
    renderEnd(make(a, { expectedSha256: "y" }))
    const panel = (await screen.findByRole("heading", { name: "Refused before the first package" })).closest("section") as HTMLElement
    expect(panel.className).toContain("bg-severity-critical/")
    expect(panel.className).toContain("border-severity-critical/")
  })

  it("interrupted: says the service stopped, when, how many it finished and how many it did not, and names no package in flight", async () => {
    const packages = [...many(52, "published"), ...many(4, "present"), ...many(45, "failed", { kind: "interrupted", reason: "interrupted" })]
    const a = attempt("interrupted", packages, {}, "interrupted")
    renderEnd(make(a))
    expect(await screen.findByRole("heading", { name: /^Stopped before it ended/ })).toBeInTheDocument()
    expect(screen.getByText(/The service stopped or restarted before this attempt ended/)).toBeInTheDocument()
    expect(screen.getByText(/at .*\d/)).toBeInTheDocument()
    expect(screen.getByText(/56 of 101 packages were finished/)).toBeInTheDocument()
    expect(screen.getByText(/45 were not finished/)).toBeInTheDocument()
    expect(screen.getByText(/counted apart from failures/)).toBeInTheDocument()
    expect(document.body.textContent ?? "").not.toMatch(/in flight|was uploading/)
    expect(screen.queryByRole("button", { name: "Retry import" })).toBeNull()
  })

  it("interrupted: names a missing end time in words", async () => {
    const a = attempt("interrupted", many(2, "published"), { endedAt: undefined })
    renderEnd(make(a))
    const heading = await screen.findByRole("heading", { name: /^Stopped before it ended/ })
    expect(within(heading).getByText(/Not recorded/)).toBeInTheDocument()
  })

  it.each([
    ["incomplete", attempt("incomplete", many(2, "failed", { kind: "nexus", reason: "x" }))],
    ["queued", attempt("", [], { status: "queued" })],
    ["running", attempt("", many(2, "published"), { status: "running" })],
  ])("shows nothing for a %s attempt", async (_name, a) => {
    const { container } = renderEnd(make(a))
    await screen.findByText("page")
    expect(container.textContent).toBe("page")
  })
})
