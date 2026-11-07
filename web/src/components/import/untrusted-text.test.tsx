import { fireEvent, render, screen } from "@testing-library/react"
import { createMemoryHistory, createRootRoute, createRouter, RouterProvider } from "@tanstack/react-router"
import { describe, expect, it } from "vitest"

import type { Attempt, Import } from "@/import/lib/outcome"

import { ArchiveRow } from "./archive-row"
import { ImportPageHeader } from "./import-header"
import { ReportList } from "./report-list"

const HOSTILE = "<img src=x onerror=alert(1)> javascript:alert(1)"

describe("text from an archive renders as text", () => {
  it("a key and a reason holding markup and a javascript link show as words", async () => {
    const root = createRootRoute({
      component: () => (
        <ul>
          <ArchiveRow archive={{ key: `packages/npm/${HOSTILE}/packages_npm.tar.gz`, size: 1, modified: "2026-11-05T08:00:00Z", importable: true }} />
          <ArchiveRow archive={{ key: "packages/npm/b/packages_npm.tar.gz", size: 1, modified: "2026-11-05T08:00:00Z", importable: false, reason: HOSTILE }} />
        </ul>
      ),
    })
    render(<RouterProvider router={createRouter({ routeTree: root, history: createMemoryHistory({ initialEntries: ["/"] }) })} />)
    expect(await screen.findAllByText(new RegExp(HOSTILE.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")))).toHaveLength(2)
    expect(document.querySelector("img")).toBeNull()
    expect(document.querySelector("a[href^='javascript' i]")).toBeNull()
    expect(document.querySelector("[onerror]")).toBeNull()
  })
})

describe("text from a report renders as text", () => {
  const hostile = (what: string) => `<img src=x onerror=alert(1)> ${what}`
  const attempt: Attempt = {
    n: 1, status: "ended", outcome: "incomplete",
    report: {
      outcome: "incomplete", reason: "", unencrypted: false, importVersion: "", archive: { file: "", sha256: "", size: 0 }, toolVersion: "", analysisId: "",
      target: { os: hostile("os"), cpu: "", libc: "", node: "", pnpmVer: "" }, nexus: { url: hostile("url"), repository: hostile("repository") },
      counts: { published: 0, present: 0, failed: 0 },
      packages: [
        { name: hostile("name"), version: hostile("version"), file: "x", state: "present", reason: "", note: hostile("note") },
        { name: "b", version: "1.0.0", file: "x", state: "failed", kind: "nexus", reason: hostile("reason"), note: "" },
      ],
    },
  }
  const imp: Import = {
    id: "i1", createdAt: "2026-11-05T09:00:00Z", expectedSha256: "", outcome: "incomplete", archiveRemoved: false,
    archive: { key: `packages/npm/${hostile("folder")}/packages_npm.tar.gz`, etag: '"e"', size: 1 }, manifest: { key: "m", etag: '"e"', size: 1 }, attempts: [attempt],
  }

  it("names, versions, notes and reasons with markup stay text", () => {
    render(
      <>
        <ImportPageHeader imp={imp} />
        <ReportList attempt={attempt} />
      </>,
    )
    fireEvent.click(screen.getByRole("button", { name: /^All/ }))
    for (const what of ["name", "version", "note", "reason", "folder", "os", "url", "repository"]) {
      expect(screen.getAllByText(new RegExp(`<img src=x onerror=alert\\(1\\)> ${what}`)).length).toBeGreaterThan(0)
    }
    expect(document.querySelector("img")).toBeNull()
    expect(document.querySelector("[onerror]")).toBeNull()
    expect(document.querySelector("a[href]")).toBeNull()
  })
})
