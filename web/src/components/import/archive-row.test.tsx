import { fireEvent, render, screen, within } from "@testing-library/react"
import { createMemoryHistory, createRootRoute, createRoute, createRouter, RouterProvider } from "@tanstack/react-router"
import { describe, expect, it, vi } from "vitest"

import type { Archive } from "@/import/api/queries"
import type { Attempt, Import, ReportPackage } from "@/import/lib/outcome"

import { ArchiveRow } from "./archive-row"

const KEY = "packages/npm/2026-11-05-reports/packages_npm.tar.gz"

const pkg = (state: string): ReportPackage => ({ name: "left-pad", version: "1.3.0", file: "x.tgz", state, reason: "", note: "" })

function attempt(outcome: string, packages: ReportPackage[], over: Partial<Attempt> = {}, reason = ""): Attempt {
  return {
    n: 1, status: "ended", outcome,
    report: {
      outcome, reason, unencrypted: false, importVersion: "0.5.0",
      archive: { file: "", sha256: "", size: 0 }, toolVersion: "", analysisId: "",
      target: { os: "", cpu: "", libc: "", node: "", pnpmVer: "" }, nexus: { url: "", repository: "" },
      counts: { published: 0, present: 0, failed: 0 }, packages,
    },
    ...over,
  }
}

const imp = (outcome: string, attempts: Attempt[]): Import => ({
  id: "20261105T090000Z-0000a001", createdAt: "2026-11-05T09:00:00Z", expectedSha256: "", outcome, archiveRemoved: false, attempts,
  archive: { key: KEY, etag: "\"a\"", size: 1 }, manifest: { key: "m", etag: "\"b\"", size: 1 },
})

const archive = (over: Partial<Archive> = {}): Archive => ({ key: KEY, size: 5_500_000, modified: "2026-11-05T08:00:00Z", importable: true, ...over })
const withLatest = (outcome: string): Archive => archive({ latestImport: { id: "20261105T090000Z-0000a001", outcome } })

function renderRow(a: Archive, latest?: Import, onStart: (a: Archive) => void = () => {}) {
  const root = createRootRoute({ component: () => <ul><ArchiveRow archive={a} latest={latest} onStart={onStart} /></ul> })
  const page = createRoute({ getParentRoute: () => root, path: "/imports/$importId", component: () => <p>page</p> })
  const router = createRouter({ routeTree: root.addChildren([page]), history: createMemoryHistory({ initialEntries: ["/"] }) })
  render(<RouterProvider router={router} />)
}

describe("ArchiveRow", () => {
  it("a row that cannot be imported gives the service's reason and the rule, and no Start", async () => {
    renderRow(archive({ importable: false, reason: "the folder holds more than one archive" }))
    await screen.findByText("Cannot be imported")
    expect(screen.getByText("the folder holds more than one archive")).toBeInTheDocument()
    expect(screen.getByText(/Keep one archive and its manifest.json side by side, at the root of packages\/npm\/ or one folder below/)).toBeInTheDocument()
    expect(screen.queryByRole("button")).not.toBeInTheDocument()
    expect(screen.queryByRole("link")).not.toBeInTheDocument()
    expect(screen.queryByText("Start")).not.toBeInTheDocument()
  })

  it("offers Start and says Not imported yet without a latest import", async () => {
    const onStart = vi.fn()
    const a = archive()
    renderRow(a, undefined, onStart)
    expect(await screen.findByText("Not imported yet")).toBeInTheDocument()
    fireEvent.click(screen.getByRole("button", { name: "Start import of 2026-11-05-reports/packages_npm.tar.gz" }))
    expect(onStart).toHaveBeenCalledWith(a)
  })

  it.each([
    ["queued", "Follow", "Follow the import of 2026-11-05-reports/packages_npm.tar.gz"],
    ["running", "Follow", "Follow the import of 2026-11-05-reports/packages_npm.tar.gz"],
    ["incomplete", "Open import", "Open import of 2026-11-05-reports/packages_npm.tar.gz"],
    ["interrupted", "Open import", "Open import of 2026-11-05-reports/packages_npm.tar.gz"],
  ])("action from the latest import: %s opens that import", async (outcome, text, name) => {
    renderRow(withLatest(outcome), imp(outcome, [attempt(outcome === "queued" || outcome === "running" ? "" : outcome, [pkg("published")])]))
    const link = await screen.findByRole("link", { name })
    expect(link).toHaveTextContent(text)
    expect(link).toHaveAttribute("href", "/imports/20261105T090000Z-0000a001")
    expect(screen.queryByRole("button", { name: /^Start/ })).not.toBeInTheDocument()
  })

  it.each(["complete", "refused"])("action from the latest import: %s offers Start", async (outcome) => {
    renderRow(withLatest(outcome), imp(outcome, [attempt(outcome, [pkg("published")], {}, "a reason")]))
    expect(await screen.findByRole("button", { name: /^Start import of/ })).toBeInTheDocument()
    expect(screen.queryByRole("link")).not.toBeInTheDocument()
  })

  it("says the outcome in words with its counts, and done of total while running", async () => {
    const failed: ReportPackage = { ...pkg("failed"), kind: "nexus", reason: "x" }
    renderRow(withLatest("incomplete"), imp("incomplete", [attempt("incomplete", [pkg("published"), pkg("published"), pkg("present"), failed])]))
    const row = within(await screen.findByRole("listitem"))
    expect(row.getByText("Incomplete")).toBeInTheDocument()
    expect(row.getByText(/published/)).toHaveTextContent("2 published")
    expect(row.getByText(/present/)).toHaveTextContent("1 present")
    expect(row.getByText(/failed/)).toHaveTextContent("1 failed")
  })

  it("says done of total while running", async () => {
    renderRow(withLatest("running"), imp("running", [attempt("", [pkg("published"), pkg("pending"), pkg("pending")], { status: "running" })]))
    expect(await screen.findByText("1 of 3 packages")).toBeInTheDocument()
    expect(screen.getByText("Running")).toBeInTheDocument()
  })

  it("complete and still listed says the archive was kept and why", async () => {
    const kept = attempt("complete", [pkg("published")], { removal: { removed: false, reason: "the archive's ETag changed after the import read it" } })
    renderRow(withLatest("complete"), imp("complete", [kept]))
    expect(await screen.findByText("Kept in MinIO: the archive's ETag changed after the import read it")).toBeInTheDocument()
  })

  it("complete with a removal reason missing says Not recorded", async () => {
    const kept = attempt("complete", [pkg("published")], { removal: { removed: false, reason: "" } })
    renderRow(withLatest("complete"), imp("complete", [kept]))
    expect(await screen.findByText("Kept in MinIO: Not recorded")).toBeInTheDocument()
  })

  it("never says kept when a removal is recorded as done", async () => {
    const gone = attempt("complete", [pkg("published")], { removal: { removed: true, reason: "" } })
    renderRow(withLatest("complete"), imp("complete", [gone]))
    expect(await screen.findByText("Recorded as removed, yet still listed.")).toBeInTheDocument()
    expect(screen.queryByText(/Kept in MinIO/)).not.toBeInTheDocument()
  })

  it("refused offers Start and shows the reason of the refusal", async () => {
    renderRow(withLatest("refused"), imp("refused", [attempt("refused", [], {}, "the archive's sha256 is aaaa but the expected sha256 is bbbb")]))
    expect(await screen.findByText("Refused")).toBeInTheDocument()
    expect(screen.getByText("the archive's sha256 is aaaa but the expected sha256 is bbbb")).toBeInTheDocument()
    expect(screen.getByRole("button", { name: /^Start import of/ })).toBeInTheDocument()
  })

  it("names the outcome without counts when the imports list has not answered", async () => {
    renderRow(withLatest("incomplete"))
    expect(await screen.findByText("Incomplete")).toBeInTheDocument()
    expect(screen.getByRole("link", { name: /^Open import of/ })).toBeInTheDocument()
  })
})
