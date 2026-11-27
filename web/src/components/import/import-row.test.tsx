import { render, screen } from "@testing-library/react"
import type { ReactNode } from "react"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import type { Import } from "@/import/lib/outcome"

import { ImportRow } from "./import-row"

vi.mock("@tanstack/react-router", () => ({
  Link: ({ to, className, children }: { to: string; className?: string; children: ReactNode }) => (
    <a href={to} className={className}>
      {children}
    </a>
  ),
}))

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] })
  vi.setSystemTime(new Date(2026, 10, 26, 14, 0))
})

afterEach(() => {
  vi.useRealTimers()
})

function imp(project?: string): Import {
  return {
    id: "i1", createdAt: new Date(2026, 10, 25, 9, 0).toISOString(), expectedSha256: "", outcome: "complete", archiveRemoved: true,
    archive: { key: "packages/npm/web-portal-2026-11-25/packages_npm.tar.gz", etag: '"a"', size: 1 },
    manifest: { key: "packages/npm/web-portal-2026-11-25/manifest.json", etag: '"b"', size: 1 },
    attempts: [{
      n: 1, status: "ended", outcome: "complete",
      report: {
        outcome: "complete", reason: "", unencrypted: false, importVersion: "", archive: { file: "packages_npm.tar.gz", sha256: "", size: 1 }, toolVersion: "", analysisId: "",
        target: { os: "", cpu: "", libc: "", node: "", pnpmVer: "" }, nexus: { url: "", repository: "" },
        counts: { published: 1, present: 0, failed: 0 }, packages: [{ name: "a", version: "1.0.0", file: "a.tgz", state: "published", reason: "", note: "" }],
        ...(project ? { crossing: { project, sealedAt: "2026-11-25T08:00:00Z", packages: 1 } } : {}),
      },
    }],
  }
}

const name = () => document.querySelector("[data-row-name]")

describe("an import of the list", () => {
  it("is named by its signed crossing once its report has one", () => {
    render(<ul><ImportRow imp={imp("web-portal")} /></ul>)
    expect(name()).toHaveTextContent("web-portal · 25 Nov")
    expect(name()).not.toHaveClass("font-mono")
    expect(screen.getByText("packages/npm/web-portal-2026-11-25/")).toBeInTheDocument()
  })

  it("is named by its folder when its report names no crossing", () => {
    render(<ul><ImportRow imp={imp()} /></ul>)
    expect(name()).toHaveTextContent("web-portal-2026-11-25/")
    expect(name()).toHaveClass("font-mono")
  })
})
