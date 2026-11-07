import { render, screen, within } from "@testing-library/react"
import { describe, expect, it } from "vitest"

import type { Attempt, Import } from "@/import/lib/outcome"

import { ImportPageHeader } from "./import-header"

const target = { os: "linux", cpu: "x64", libc: "glibc", node: "22.17.1", pnpmVer: "12.3.4" }
const blank = { os: "", cpu: "", libc: "", node: "", pnpmVer: "" }

function attempt(over: Partial<Attempt> = {}, report: Partial<Attempt["report"]> = {}): Attempt {
  return {
    n: 2, status: "ended", outcome: "incomplete", startedAt: "2026-11-05T09:12:00Z", endedAt: "2026-11-05T09:20:00Z",
    report: {
      outcome: "incomplete", reason: "", unencrypted: false, importVersion: "0.5.0",
      archive: { file: "packages_npm.tar.gz", sha256: "a".repeat(64), size: 5_500_000 }, toolVersion: "0.4.0", analysisId: "",
      target, nexus: { url: "http://nexus.lab:8081", repository: "npm-hosted" },
      counts: { published: 0, present: 0, failed: 0 }, packages: [], ...report,
    },
    ...over,
  }
}

function imp(a: Attempt, key = "packages/npm/2026-11-05-billing-api/packages_npm.tar.gz"): Import {
  return {
    id: "20261105T090000Z-a1", createdAt: "2026-11-05T09:00:00Z", expectedSha256: "", outcome: a.status === "ended" ? a.outcome : a.status, archiveRemoved: false,
    archive: { key, etag: '"e1"', size: 5_500_000 }, manifest: { key: "packages/npm/2026-11-05-billing-api/manifest.json", etag: '"e2"', size: 1200 },
    attempts: [a],
  }
}

function value(label: string): string {
  const term = screen.getByText(label, { selector: "dt" })
  return (term.nextElementSibling as HTMLElement).textContent ?? ""
}

describe("import header", () => {
  it("names the archive, its folder, the outcome and the attempt", () => {
    render(<ImportPageHeader imp={imp(attempt())} />)
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent("packages_npm.tar.gz")
    expect(screen.getByText("2026-11-05-billing-api/")).toBeInTheDocument()
    expect(screen.getByText("Incomplete")).toBeInTheDocument()
    expect(value("Attempt")).toBe("2")
  })

  it("shows the start time, the archive size, Nexus and the target", () => {
    render(<ImportPageHeader imp={imp(attempt())} />)
    expect(value("Started")).not.toMatch(/Not/)
    expect(value("Started")).toMatch(/\d/)
    expect(value("Archive size")).toBe("5.2 MB")
    expect(value("Nexus repository")).toBe("npm-hosted")
    expect(value("Nexus address")).toBe("http://nexus.lab:8081")
    expect(value("Target OS")).toBe("linux")
    expect(value("CPU")).toBe("x64")
    expect(value("libc")).toBe("glibc")
    expect(value("Node")).toBe("22.17.1")
    expect(value("pnpm")).toBe("12.3.4")
  })

  it("says Not read for every value the attempt never read", () => {
    render(<ImportPageHeader imp={imp(attempt({}, { target: blank, nexus: { url: "", repository: "" } }))} />)
    for (const label of ["Nexus repository", "Nexus address", "Target OS", "CPU", "libc", "Node", "pnpm"]) {
      expect(value(label)).toBe("Not read")
    }
  })

  it("says Not started yet for the start of a queued attempt", () => {
    render(<ImportPageHeader imp={imp(attempt({ n: 1, status: "queued", outcome: "", startedAt: undefined }))} />)
    expect(value("Started")).toBe("Not started yet")
    expect(screen.getByText("Queued")).toBeInTheDocument()
  })

  it("says Not recorded for an ended attempt with no start time", () => {
    render(<ImportPageHeader imp={imp(attempt({ startedAt: undefined }))} />)
    expect(value("Started")).toBe("Not recorded")
  })

  it("names plain http when the report says so", () => {
    render(<ImportPageHeader imp={imp(attempt({}, { unencrypted: true }))} />)
    const note = screen.getByText(/plain http/i)
    expect(note).toHaveTextContent(/Nexus, MinIO or the key set is reached unencrypted/)
  })

  it("keeps quiet about plain http when the report does not say so", () => {
    render(<ImportPageHeader imp={imp(attempt())} />)
    expect(screen.queryByText(/plain http/i)).toBeNull()
  })

  it("wraps a 1,024-byte key", () => {
    const key = `packages/npm/${"k".repeat(1024 - 13 - 1 - 19)}/packages_npm.tar.gz`
    render(<ImportPageHeader imp={imp(attempt(), key)} />)
    const folder = screen.getByText(/^k+\/$/)
    expect(within(folder.parentElement as HTMLElement).getByRole("heading", { level: 1 })).toBeInTheDocument()
    expect(folder.className).toContain("[overflow-wrap:anywhere]")
  })
})
